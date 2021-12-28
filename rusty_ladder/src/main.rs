/**********************************************************************

Copyright (C) 2021 by reddal

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

**********************************************************************/

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::default_trait_access)]

use config::Config;
use std::{
	borrow::Cow,
	fs::File,
	io::{self, Read},
	sync::Arc,
};
use structopt::StructOpt;
use tokio::runtime::Runtime;

type BoxStdErr = Box<dyn std::error::Error + Send + Sync>;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONF_FORMAT: ConfigFormat = ConfigFormat::Toml;

#[cfg(feature = "use-tui")]
mod tui;

#[derive(StructOpt)]
#[structopt(name = "rusty_ladder")]
pub struct AppOptions {
	/// Enable TUI.
	#[structopt(long)]
	tui: bool,

	/// Set the format of the config file. Can be 'toml' (default) or 'json'.
	#[structopt(short, long)]
	format: Option<String>,

	/// Read config from file. STDIN will be used if not specified.
	#[structopt(short, long)]
	config: Option<String>,

	/// Print version.
	#[structopt(long)]
	version: bool,
}

enum ConfigFormat {
	Toml,
	Json,
}

impl ConfigFormat {
	fn from_str(s: &str) -> Option<Self> {
		let mut s = s.to_string();
		s.make_ascii_lowercase();
		Some(match s.as_str() {
			"toml" => Self::Toml,
			"json" => Self::Json,
			_ => return None,
		})
	}
}

fn read_conf_str(path: Option<&str>) -> Result<String, std::io::Error> {
	let mut conf_str = String::with_capacity(1024);
	if let Some(path) = path {
		File::open(path)?.read_to_string(&mut conf_str)?;
	} else {
		std::io::stdin().read_to_string(&mut conf_str)?;
	}
	Ok(conf_str)
}

fn read_config(conf_str: &str, format: &ConfigFormat) -> Result<Config, BoxStdErr> {
	let conf: Config = match format {
		ConfigFormat::Toml => toml::from_str(conf_str)?,
		ConfigFormat::Json => serde_json::from_str(conf_str)?,
	};
	Ok(conf)
}

#[derive(Debug, thiserror::Error)]
enum Error {
	#[error("[IO error] {0}")]
	Io(#[from] io::Error),
	#[error("[input] {0}")]
	Input(Cow<'static, str>),
	#[error("[config] {0}")]
	Config(BoxStdErr),
	#[error("[runtime] {0}")]
	Runtime(BoxStdErr),
}

fn serve(opts: &AppOptions) -> Result<(), Error> {
	let conf = {
		let format = if let Some(s) = &opts.format {
			ConfigFormat::from_str(s).ok_or_else(|| {
				Error::Input(format!("unknown config format from settings value '{}'", s).into())
			})?
		} else {
			DEFAULT_CONF_FORMAT
		};

		let conf_str = read_conf_str(opts.config.as_deref())
			.map_err(|e| Error::Input(format!("cannot read config: {}", e).into()))?;

		read_config(&conf_str, &format).map_err(Error::Config)?
	};

	let rt = Runtime::new()?;

	#[cfg(feature = "use-tui")]
	{
		let use_tui = opts.tui;
		tui_utils::run_with_tui(use_tui, conf, rt).map_err(Error::Runtime)?;
	}
	#[cfg(not(feature = "use-tui"))]
	{
		if opts.tui {
			return Err(Error::Input(
				"feature `use-tui` must be enabled to use TUI".into(),
			));
		}
		// Initialize logger
		init_logger(&conf.log).map_err(Error::Config)?;
		let server = Arc::new(
			conf.server
				.build()
				.map_err(|e| Error::Config(Box::new(e)))?,
		);
		if let Err(err) = rt.block_on(server.serve(None)) {
			return Err(Error::Runtime(err));
		};
	}

	Ok(())
}

fn main() {
	let opts = AppOptions::from_args();
	if opts.version {
		println!("{}", VERSION);
		return;
	}
	if let Err(err) = serve(&opts) {
		println!("Error happened during initialization:\n {}\n", err);
		std::process::exit(match err {
			Error::Io(_) => exitcode::IOERR,
			Error::Input(_) | Error::Config(_) => exitcode::CONFIG,
			Error::Runtime(_) => exitcode::SOFTWARE,
		});
	}
}

#[cfg(feature = "use-tui")]
mod tui_utils {
	use super::{config::Config, init_logger, tui, Arc, BoxStdErr, Runtime};
	use futures::future::abortable;
	use ladder_lib::Monitor;
	use log::debug;
	use std::{sync::mpsc, thread};

	pub fn run_with_tui(use_tui: bool, conf: Config, rt: Runtime) -> Result<(), BoxStdErr> {
		if use_tui && conf.log.output.is_empty() {
			return Err(format!(
				"Cannot use TUI when 'output' in settings is empty (currently '{}')",
				conf.log.output
			)
			.into());
		}

		// Initialize logger
		init_logger(&conf.log)?;

		let rt = Arc::new(rt);

		let server = Arc::new(conf.server.build()?);

		if use_tui {
			use futures::FutureExt;
			let (tui_sender, tui_receiver) = mpsc::channel();
			let (monitor, mon_task) = Monitor::new();
			// Abort the serve task if gui says so.
			let task = {
				let mon_task = mon_task.map(|_| Ok(()));
				let serve_task = server.serve(Some(monitor.clone()));
				futures::future::try_join(serve_task, mon_task)
			};
			let (serve_task, abort_handle) = abortable(task);

			// Spawn a thread to handle TUI
			let tui_thread = {
				thread::spawn(move || {
					let res = tui::run(tui_receiver, tui::DEFAULT_UPDATE_INTERVAL, monitor);
					// This error is caused by server thread panicking, so it's safe to ignore.
					abort_handle.abort();
					res
				})
			};

			// Handling serve result
			let result = match rt.block_on(serve_task) {
				Ok(result) => result,
				Err(_aborted) => {
					debug!("Serve task is aborted");
					return Ok(());
				}
			};
			if let Err(err) = result {
				tui_sender.send(()).unwrap_or_default();
				// Wait for gui thread to stop
				match tui_thread.join() {
					Ok(Err(e)) => {
						log::error!("TUI thread error: {}.", e);
					}
					Err(e) => {
						// Panic the whole thing if a thread panic.
						std::panic::resume_unwind(e);
					}
					Ok(_) => {}
				};
				return Err(err);
			};
		} else if let Err(err) = rt.block_on(server.serve(None)) {
			return Err(err);
		}

		Ok(())
	}
}

fn init_logger(conf: &config::Log) -> Result<(), BoxStdErr> {
	let time_format =
		time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z").unwrap();
	let colors = fern::colors::ColoredLevelConfig::new().info(fern::colors::Color::Blue);
	let is_output_to_std = conf.output.is_empty();
	let dispatch = fern::Dispatch::new()
		.level(conf.level)
		.format(move |out, message, record| {
			let now_str = time::OffsetDateTime::now_utc()
				.format(&time_format)
				.unwrap();
			let target = if record.level() <= log::Level::Info {
				// For info, warn, error
				""
			} else {
				record.target()
			};
			if is_output_to_std {
				out.finish(format_args!(
					"[{} {} {}] {}",
					now_str,
					colors.color(record.level()),
					target,
					message
				));
			} else {
				out.finish(format_args!(
					"[{} {} {}] {}",
					now_str,
					record.level(),
					target,
					message
				));
			}
		});
	if is_output_to_std {
		// Use stdout
		dispatch.chain(std::io::stdout()).apply()?;
	} else {
		// Use file
		dispatch.chain(fern::log_file(&conf.output)?).apply()?;
	}
	Ok(())
}

mod config {
	use ladder_lib::ServerBuilder;
	use log::LevelFilter;
	use serde::Deserialize;

	#[derive(Deserialize)]
	#[serde(deny_unknown_fields)]
	pub struct Log {
		#[serde(default = "default_log_level")]
		pub level: LevelFilter,
		#[serde(default)]
		pub output: String,
	}

	impl Default for Log {
		fn default() -> Self {
			Log {
				level: default_log_level(),
				output: String::new(),
			}
		}
	}

	#[derive(Deserialize)]
	pub struct Config {
		#[serde(default)]
		pub log: Log,
		#[serde(flatten)]
		pub server: ServerBuilder,
	}

	fn default_log_level() -> LevelFilter {
		LevelFilter::Info
	}
}
