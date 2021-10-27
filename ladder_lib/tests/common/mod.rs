mod http_server;
mod tcp;
mod udp;

use ladder_lib::{Server, ServerBuilder};
use lazy_static::lazy_static;
use log::error;
use std::{
	error::Error as StdErr,
	ffi::OsStr,
	io::{self, Read},
	path::{Path, PathBuf},
	process::{Child, Command, Stdio},
	sync::Arc,
	thread,
	time::Duration,
};
use thread::JoinHandle;

type BoxStdErr = Box<dyn StdErr + Send + Sync>;

const CHILD_INIT_TIME: Duration = Duration::from_millis(200);
const HTTP_SERVER_ADDR: &str = "127.0.0.1:44337";
const HTTP_SERVER_URL: &str = "http://127.0.0.1:44337";

const UDP_PROXY_ADDR: ([u8; 4], u16) = ([127, 0, 0, 1], 32211);
const UDP_ECHO_ADDR: ([u8; 4], u16) = ([127, 0, 0, 1], 9876);

lazy_static! {
	static ref V2RAY_PATH: String =
		std::env::var("V2RAY_PATH").expect("Invalid or empty environment variable V2RAY_PATH");
	// static ref CONF_DIR: String =
	// 	std::env::var("CONF_DIR").expect("Invalid or empty environment variable CONF_DIR");
	static ref CONF_DIR: String = String::from("tests/configs");
	static ref SERVED_DATA: String = "This is something, what do you expect.".repeat(256);
}

pub struct Tester {
	v2ray_bin: PathBuf,
	test_config_dir: PathBuf,
}

impl Tester {
	pub fn new() -> Self {
		// Go to parent directory temporarily (currently in ladder_lib/)
		// to canonicalize v2ray_bin.
		let v2ray_bin = {
			use std::env;
			let curr_dir = env::current_dir().expect("Cannot get current work directory.");
			let mut v2ray_path = curr_dir
				.canonicalize()
				.expect("Cannot get canonicalized current work directory.")
				.parent()
				.expect("Current work directory have no parent.")
				.to_owned();
			v2ray_path.push(V2RAY_PATH.as_str());
			v2ray_path.canonicalize().expect("Cannot find v2ray")
		};

		Self {
			v2ray_bin,
			test_config_dir: Path::new(CONF_DIR.as_str())
				.canonicalize()
				.unwrap_or_else(|_| {
					panic!(
						"Test configuration directory '{}' does not exist",
						CONF_DIR.as_str()
					)
				}),
		}
	}

	fn spawn_v2ray(&self, conf_path: &Path) -> Result<ChildGuard, BoxStdErr> {
		let config_str = OsStr::new("--config");

		spawn_child(
			"v2ray",
			&self.v2ray_bin,
			&[config_str, conf_path.as_ref()],
			Path::new(&conf_path).parent().unwrap(),
		)
	}
}

pub fn setup_logger() {
	let _ = env_logger::builder().is_test(true).try_init();
}

struct ChildGuard {
	child: Child,
	stdout_thread: Option<JoinHandle<()>>,
	running: bool,
}

impl ChildGuard {
	fn new(mut child: Child, label: &str) -> Result<Self, BoxStdErr> {
		let stdout = child.stdout.take().unwrap();
		let _stderr = child.stderr.take().unwrap();

		let label = label.to_owned();

		let stdout_thread = thread::spawn(move || {
			print_output(stdout, &label);
		});

		Ok(Self {
			child,
			stdout_thread: Some(stdout_thread),
			running: true,
		})
	}

	fn kill(&mut self) {
		if self.running {
			println!("Killing child process");
			if let Err(err) = self.child.kill() {
				error!("TestProcess is already closed ({})", err)
			}
			self.running = false;
		}
	}

	fn kill_and_wait(mut self) {
		self.kill();
		if let Some(thread) = self.stdout_thread.take() {
			if let Err(e) = thread.join() {
				if let Some(e) = e.downcast_ref::<&'static str>() {
					println!("stdout thread panic ({})", e);
				} else {
					println!("stdout thread panic with unknown error");
				}
			}
		}
	}
}

impl Drop for ChildGuard {
	fn drop(&mut self) {
		self.kill()
	}
}

fn print_output<R: Read>(mut output: R, label: &str) {
	let mut buffer = [0_u8; 4 * 1024];
	loop {
		let len = match output.read(&mut buffer) {
			Ok(len) => len,
			Err(err) => {
				println!("{} error ({}).", label, err);
				break;
			}
		};
		if len == 0 {
			println!("{} stopped.", label);
			break;
		}
		let buffer = &buffer[..len];
		let content = match std::str::from_utf8(buffer) {
			Ok(content) => content,
			Err(err) => {
				println!("{} error: output is not utf8 ({}).", label, err);
				break;
			}
		};
		for line in content.split('\n') {
			if !line.is_empty() {
				println!("[{}] {}", label, line);
			}
		}
	}
}

fn read_server_config(conf_path: &Path) -> Result<Arc<Server>, BoxStdErr> {
	let empty_args: [(&str, &str); 0] = [];
	read_server_config_args(conf_path, empty_args.iter().copied())
}

fn read_server_config_args<'a, I>(conf_path: &Path, args: I) -> Result<Arc<Server>, BoxStdErr>
where
	I: IntoIterator<Item = (&'a str, &'a str)>,
{
	log::warn!("Reading config file '{}'", conf_path.to_str().unwrap());

	// Read file content into memory, and replace all keywords
	let mut content = std::fs::read_to_string(conf_path)?;
	for (from, to) in args {
		let key = format!("${}", from);
		content = content.replace(&key, to);
	}
	let cursor = io::Cursor::new(content);

	log::warn!(
		"Building server, cwd: {}",
		std::env::current_dir()?.to_str().unwrap()
	);
	let server_result = read_and_build(cursor);

	let server = server_result?;

	Ok(Arc::new(server))
}

fn read_and_build(mut stream: impl std::io::Read) -> Result<Server, BoxStdErr> {
	let mut file_content = String::new();
	stream.read_to_string(&mut file_content)?;
	let builder: ServerBuilder = toml::from_str(&file_content)?;
	Ok(builder.build()?)
}

fn spawn_child<S: AsRef<OsStr>, I: IntoIterator<Item = S>>(
	label: &str,
	bin: &Path,
	args: I,
	cwd: &Path,
) -> Result<ChildGuard, BoxStdErr> {
	let child = Command::new(bin)
		.args(args)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.current_dir(cwd)
		.spawn()?;
	thread::sleep(CHILD_INIT_TIME);
	ChildGuard::new(child, label)
}

trait CloneAndPush {
	fn clone_push(&self, path: impl AsRef<Path>) -> Self;
}

impl CloneAndPush for PathBuf {
	fn clone_push(&self, path: impl AsRef<Path>) -> Self {
		let mut res = self.clone();
		res.push(path);
		res
	}
}
