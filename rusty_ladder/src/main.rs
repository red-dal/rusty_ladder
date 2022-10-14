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

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::default_trait_access)]

// TODO: log to TUI
use config::{Config, LogOutput};
use std::{io, str::FromStr, sync::Arc};
use structopt::StructOpt;
use tokio::runtime::Runtime;

type BoxStdErr = Box<dyn std::error::Error + Send + Sync>;

const VERSION: &str = env!("CARGO_PKG_VERSION");

macro_rules! make_feature_str {
	($name: literal) => {
		#[cfg(feature = $name)]
		$name
	};
}

const FEATURES: &[&str] = &[
	make_feature_str!("parse-url"),
	make_feature_str!("parse-url-v2rayn"),
	make_feature_str!("parse-config"),
	make_feature_str!("use-tui"),
	make_feature_str!("use-udp"),
	make_feature_str!("use-webapi"),
	make_feature_str!("use-protobuf"),
	make_feature_str!("use-router-regex"),
	// DNS
	make_feature_str!("local-dns"),
	make_feature_str!("local-dns-over-openssl"),
	make_feature_str!("local-dns-over-rustls"),
	// Transport
	make_feature_str!("ws-transport-openssl"),
	make_feature_str!("tls-transport-openssl"),
	make_feature_str!("h2-transport-openssl"),
	make_feature_str!("ws-transport-rustls"),
	make_feature_str!("tls-transport-rustls"),
	make_feature_str!("h2-transport-rustls"),
	// Proxy
	make_feature_str!("socks5-inbound"),
	make_feature_str!("socks5-outbound"),
	make_feature_str!("http-inbound"),
	make_feature_str!("http-outbound"),
	make_feature_str!("shadowsocks-inbound-openssl"),
	make_feature_str!("shadowsocks-outbound-openssl"),
	make_feature_str!("shadowsocks-inbound-ring"),
	make_feature_str!("shadowsocks-outbound-ring"),
	make_feature_str!("vmess-inbound-openssl"),
	make_feature_str!("vmess-outbound-openssl"),
	make_feature_str!("vmess-inbound-ring"),
	make_feature_str!("vmess-outbound-ring"),
	make_feature_str!("chain-outbound"),
	make_feature_str!("trojan-outbound"),
];

#[cfg(all(not(feature = "parse-url"), not(feature = "parse-config")))]
compile_error!("At least one of the features ['parse-url', 'parse-config'] must be enabled");

#[cfg(feature = "use-tui")]
mod tui;

#[derive(StructOpt)]
#[structopt(name = "rusty_ladder")]
pub struct AppOptions {
	/// Enable TUI.
	#[structopt(long)]
	tui: bool,

	/// Set the format of the config file. Can be 'toml' (default) or 'json'.
	#[cfg(feature = "parse-config")]
	#[structopt(short, long, name = "CONF_FORMAT")]
	format: Option<ConfigFormat>,

	/// Read config from file.
	#[cfg(feature = "parse-config")]
	#[structopt(short, long, name = "CONF_PATH")]
	config: Option<String>,

	/// Print version.
	#[structopt(long)]
	version: bool,

	/// Set inbound URL.
	#[cfg(feature = "parse-url")]
	#[structopt(short, long, name = "INBOUND_URL")]
	inbound: Option<String>,

	/// Set outbound URL.
	#[cfg(feature = "parse-url")]
	#[structopt(short, long, name = "OUTBOUND_URL")]
	outbound: Option<String>,

	#[cfg(feature = "parse-url")]
	/// Block an IP, network (x.x.x.x/xx) or domain.
	#[structopt(short, long, verbatim_doc_comment, name = "BLOCK_LIST")]
	block: Vec<String>,

	#[cfg(feature = "parse-url")]
	/// Allow access to LAN and local IPs, which is forbidden by default.
	#[structopt(long)]
	allow_lan: bool,

	/// Set the log level. Must be one of ["debug", "info", "warn" (default), "error"]
	#[structopt(long, name = "LOG_LEVEL")]
	log: Option<log::LevelFilter>,

	/// Set the output file for log.
	#[structopt(long, name = "LOG_FILE")]
	log_out: Option<String>,
}

impl AppOptions {
	fn into_action(self) -> Result<Action, BoxStdErr> {
		if self.version {
			return Ok(Action::CheckVersion);
		}

		let log_out = if let Some(log_out) = self.log_out {
			LogOutput::from_str(&log_out)
		} else if self.tui {
			None
		} else {
			Some(LogOutput::Stdout)
		};

		let coms = ActionCommons {
			use_tui: self.tui,
			log: self.log,
			log_out,
		};

		if !cfg!(feature = "use-tui") && coms.use_tui {
			return Err("feature 'use-tui' not enabled".into());
		}

		#[cfg(feature = "parse-url")]
		match (self.inbound, self.outbound) {
			(None, None) => {
				// Do nothing
			}
			(Some(_), None) => return Err("missing --outbound".into()),
			(None, Some(_)) => return Err("missing --inbound".into()),
			(Some(in_url), Some(out_url)) => {
				#[cfg(feature = "parse-config")]
				if self.config.is_some() {
					return Err("option --inbound and --outbound incompatible with --config".into());
				}
				return Ok(Action::Serve(ServeAction::Url {
					coms,
					in_url,
					out_url,
					block_list: self.block,
					allow_lan: self.allow_lan,
				}));
			}
		}

		#[cfg(feature = "parse-config")]
		if let Some(path) = self.config {
			let path = std::path::PathBuf::from(path);
			let format = self.format.unwrap_or_else(|| {
				let mut format = ConfigFormat::default();
				if let Some(ext) = path.extension() {
					if ext.eq_ignore_ascii_case("toml") {
						format = ConfigFormat::Toml;
					}
				}
				format
			});
			return Ok(Action::Serve(ServeAction::File { coms, path, format }));
		}

		Err("missing arguments".into())
	}
}

enum Action {
	CheckVersion,
	Serve(ServeAction),
}

struct ActionCommons {
	use_tui: bool,
	log: Option<log::LevelFilter>,
	log_out: Option<LogOutput>,
}

enum ServeAction {
	#[cfg(feature = "parse-config")]
	File {
		coms: ActionCommons,
		path: std::path::PathBuf,
		format: ConfigFormat,
	},
	#[cfg(feature = "parse-url")]
	Url {
		coms: ActionCommons,
		in_url: String,
		out_url: String,
		block_list: Vec<String>,
		allow_lan: bool,
	},
}

#[cfg(feature = "parse-config")]
mod parse_config_impl;
#[cfg(feature = "parse-config")]
use parse_config_impl::{make_config, ConfigFormat};

#[cfg(feature = "parse-url")]
mod parse_url_impl;
#[cfg(feature = "parse-url")]
use parse_url_impl::make_config_from_args;

#[derive(Debug, thiserror::Error)]
enum Error {
	#[error("[IO error] {0}")]
	Io(#[from] io::Error),
	#[error("[input] {0}")]
	Input(BoxStdErr),
	#[allow(dead_code)]
	#[error("[config] {0}")]
	Config(BoxStdErr),
	#[error("[runtime] {0}")]
	Runtime(BoxStdErr),
}

impl Error {
	#[allow(dead_code)]
	#[inline]
	pub fn input(s: impl Into<BoxStdErr>) -> Self {
		Self::Input(s.into())
	}

	#[allow(dead_code)]
	#[inline]
	pub fn config(s: impl Into<BoxStdErr>) -> Self {
		Self::Config(s.into())
	}
}

fn serve(act: ServeAction) -> Result<(), Error> {
	#[cfg(feature = "use-tui")]
	let mut use_tui = false;

	let conf = match act {
		#[cfg(feature = "parse-config")]
		ServeAction::File { coms, path, format } => {
			use std::io::Read;
			#[cfg(feature = "use-tui")]
			if coms.use_tui {
				use_tui = true;
			}
			let mut conf_str = String::new();
			std::fs::File::open(path)
				.map_err(Error::config)?
				.read_to_string(&mut conf_str)
				.map_err(Error::config)?;
			make_config(format, &conf_str, coms)?
		}
		#[cfg(feature = "parse-url")]
		ServeAction::Url {
			coms,
			in_url,
			out_url,
			block_list,
			allow_lan,
		} => {
			#[cfg(feature = "use-tui")]
			if coms.use_tui {
				use_tui = true;
			}
			make_config_from_args(&in_url, &out_url, allow_lan, &block_list, coms)?
		}
	};

	let rt = Runtime::new()?;

	#[cfg(feature = "use-tui")]
	{
		tui_utils::run_with_tui(use_tui, conf, rt).map_err(Error::Runtime)?;
	}
	#[cfg(not(feature = "use-tui"))]
	{
		use ladder_lib::protocol::DisplayInfo;
		// Initialize logger
		conf.log.init_logger().map_err(Error::Config)?;
		for inb in &conf.server.inbounds {
			log::info!("Found inbound: {}", inb.detail());
		}
		for outb in &conf.server.outbounds {
			log::info!("Found outbound: {}", outb.detail());
		}
		log::info!("Found {} routing rules.", conf.server.router.rules.len());
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

fn format_version() -> String {
	let mut features_msg = String::new();
	for (index, feature) in FEATURES.iter().enumerate() {
		if index != 0 {
			features_msg.push(',');
		}
		features_msg.push_str(feature);
	}
	format!("{}\nFeatures: {}", VERSION, features_msg)
}

fn main() -> Result<(), BoxStdErr> {
	let action = AppOptions::from_args().into_action()?;
	match action {
		Action::CheckVersion => {
			println!("{}", format_version());
		}
		Action::Serve(act) => {
			serve(act)?;
		}
	};
	Ok(())
}

#[cfg(feature = "use-tui")]
mod tui_utils {
	use super::{config::Config, tui, Arc, BoxStdErr, Runtime};
	use futures::future::abortable;
	use ladder_lib::{protocol::DisplayInfo, Monitor};
	use log::debug;
	use std::{sync::mpsc, thread};

	pub fn run_with_tui(use_tui: bool, conf: Config, rt: Runtime) -> Result<(), BoxStdErr> {
		if use_tui && matches!(&conf.log.output, Some(super::config::LogOutput::Stdout)) {
			return Err("cannot use stdout for log when using TUI".into());
		}
		conf.log.init_logger()?;

		for inb in &conf.server.inbounds {
			log::info!("Found inbound: {}", inb.detail());
		}
		for outb in &conf.server.outbounds {
			log::info!("Found outbound: {}", outb.detail());
		}
		log::info!("Found {} routing rules.", conf.server.router.rules.len());
		let server = Arc::new(conf.server.build()?);

		if use_tui {
			use futures::FutureExt;
			let tui = tui::Tui::new(&server);
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
			let tui_thread = thread::spawn(move || {
				let res = tui.run(tui_receiver, tui::DEFAULT_UPDATE_INTERVAL, &monitor);
				// This error is caused by server thread panicking, so it's safe to ignore.
				abort_handle.abort();
				res
			});

			// Handling serve result
			let rt = Arc::new(rt);
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

// ----------------------------------------------------------
//                          Config
// ----------------------------------------------------------

mod config {
	use crate::BoxStdErr;
	use fern::colors::{Color, ColoredLevelConfig};
	use ladder_lib::ServerBuilder;
	use log::{Level, LevelFilter};

	// ------------------- Logging -------------------
	const STR_STDOUT: &str = "@stdout";
	const STR_STDERR: &str = "@stderr";
	const STR_NONE: &str = "@none";

	pub enum LogOutput {
		Stdout,
		Stderr,
		File(String),
	}

	impl LogOutput {
		pub fn is_colorful(&self) -> bool {
			matches!(self, Self::Stdout | Self::Stderr)
		}

		pub fn from_str(s: &str) -> Option<Self> {
			match s {
				STR_NONE => None,
				STR_STDOUT | "" => Some(LogOutput::Stdout),
				STR_STDERR => Some(LogOutput::Stderr),
				_ => Some(LogOutput::File(s.to_string())),
			}
		}
	}

	#[cfg(feature = "parse-config")]
	fn deserialize_output<'de, D>(deserializer: D) -> Result<Option<LogOutput>, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = <&str as serde::Deserialize<'de>>::deserialize(deserializer)?;
		Ok(LogOutput::from_str(s))
	}

	#[cfg_attr(
		feature = "parse-config",
		derive(serde::Deserialize),
		serde(deny_unknown_fields)
	)]
	pub struct Log {
		#[cfg_attr(feature = "parse-config", serde(default = "default_log_level"))]
		pub level: LevelFilter,
		#[cfg_attr(
			feature = "parse-config",
			serde(default = "default_output"),
			serde(deserialize_with = "deserialize_output"),
			serde(rename = "output")
		)]
		pub output: Option<LogOutput>,
	}

	impl Log {
		/// Initialize logger.
		///
		/// DO NOT call this function more than once!
		pub fn init_logger(&self) -> Result<(), BoxStdErr> {
			if let Some(output) = &self.output {
				let time_format = time::format_description::parse(
					"[year]-[month]-[day]T[hour]:[minute]:[second]Z",
				)
				.unwrap();
				let is_colorful = output.is_colorful();
				let colors = ColoredLevelConfig::new()
					.info(Color::Blue)
					.trace(Color::Magenta);
				let levels: &[String; 5] = {
					let strs = if is_colorful {
						[
							colors.color(Level::Error).to_string(),
							colors.color(Level::Warn).to_string(),
							colors.color(Level::Info).to_string(),
							colors.color(Level::Debug).to_string(),
							colors.color(Level::Trace).to_string(),
						]
					} else {
						[
							Level::Error.to_string(),
							Level::Warn.to_string(),
							Level::Info.to_string(),
							Level::Debug.to_string(),
							Level::Trace.to_string(),
						]
					};
					// This function should only be called once,
					// so it is ok to leak.
					Box::leak(Box::new(strs))
				};
				let dispatch =
					fern::Dispatch::new()
						.level(self.level)
						.format(move |out, message, record| {
							let time = time::OffsetDateTime::now_utc()
								.format(&time_format)
								.unwrap();
							let level = match record.level() {
								Level::Error => levels[0].as_str(),
								Level::Warn => levels[1].as_str(),
								Level::Info => levels[2].as_str(),
								Level::Debug => levels[3].as_str(),
								Level::Trace => levels[4].as_str(),
							};
							// Ignore target for any level above DEBUG
							// let target = if record.level() <= Level::Info {
							// 	""
							// } else {
							// 	record.target()
							// };
							let target = record.target();
							out.finish(format_args!("[{time} {level} {target}] {message}"));
						});
				match &output {
					LogOutput::Stdout => dispatch.chain(std::io::stdout()),
					LogOutput::Stderr => dispatch.chain(std::io::stderr()),
					LogOutput::File(f) => dispatch.chain(fern::log_file(f)?),
				}
				.apply()?;
			}
			// Ignore empty output
			Ok(())
		}
	}

	impl Default for Log {
		fn default() -> Self {
			Log {
				level: default_log_level(),
				output: Some(LogOutput::Stdout),
			}
		}
	}

	fn default_log_level() -> LevelFilter {
		LevelFilter::Info
	}

	#[allow(clippy::unnecessary_wraps)]
	#[allow(dead_code)]
	fn default_output() -> Option<LogOutput> {
		Some(LogOutput::Stdout)
	}

	// ------------------- Config -------------------
	#[cfg_attr(feature = "parse-config", derive(serde::Deserialize))]
	pub struct Config {
		#[cfg_attr(feature = "parse-config", serde(default))]
		pub log: Log,
		#[cfg_attr(feature = "parse-config", serde(flatten))]
		pub server: ServerBuilder,
	}
}
