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

use config::Config;
use std::{borrow::Cow, io, str::FromStr, sync::Arc};
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
	make_feature_str!("vmess-legacy-auth"),
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
	///
	/// This only works if '--config' is specified.
	#[cfg(feature = "parse-config")]
	#[structopt(short, long, name = "CONF_FORMAT")]
	format: Option<ConfigFormat>,

	/// Read config from file. STDIN will be used if not specified.
	#[cfg(feature = "parse-config")]
	#[structopt(short, long, name = "CONF_PATH")]
	config: Option<String>,

	/// Print version.
	#[structopt(long)]
	version: bool,

	/// Set inbound URL.
	///
	/// Using this will ignore '--config'.
	/// '--inbound' and '--outbound' must be both set or both empty.
	#[cfg(feature = "parse-url")]
	#[structopt(short, long, name = "INBOUND_URL")]
	inbound: Option<String>,

	/// Set outbound URL.
	///
	/// Using this will ignore '--config'.
	/// '--inbound' and '--outbound' must be both set or both empty.
	#[cfg(feature = "parse-url")]
	#[structopt(short, long, name = "OUTBOUND_URL")]
	outbound: Option<String>,

	/// Block request to these addresees (separated by ',')
	///
	/// Each address can be either an IP (like "127.0.0.1") or a subnet (like "127.0.0.0/8").
	///
	/// Some special addresses are reserved:
	/// - "$lan": private network like 192.168.0.0/16
	/// - "$localloop": local loop like 127.0.0.0/8
	///
	/// "$lan,$localloop" will be used if not set.
	///
	/// Set to "" to use an empty block list.
	///
	/// This only works if '--inbound' and '--outbound' is set.
	#[cfg(feature = "parse-url")]
	#[structopt(long, verbatim_doc_comment, name = "BLOCK_LIST")]
	block: Option<String>,

	/// Set the log level. Must be one of ["debug", "info", "warn", "error"]
	///
	/// If not specified, "warn" will be used.
	/// This only works if '--inbound' and '--outbound' is set.
	#[cfg(feature = "parse-url")]
	#[structopt(long, name = "LOG_LEVEL")]
	log: Option<log::LevelFilter>,

	/// Set the path for log file.
	///
	/// If not specified, STDOUT will be used as log output.
	/// This only works if '--inbound' and '--outbound' is set.
	#[cfg(feature = "parse-url")]
	#[structopt(long, name = "LOG_FILE")]
	log_file: Option<String>,
}

#[cfg(feature = "parse-config")]
mod parse_config_impl {
	use super::{AppOptions, BoxStdErr, Config, Error, FromStr};
	use std::borrow::Cow;
	use std::{fs::File, io::Read};

	#[derive(Clone, Copy)]
	pub(super) enum ConfigFormat {
		Toml,
		Json,
	}

	impl FromStr for ConfigFormat {
		type Err = Cow<'static, str>;

		fn from_str(s: &str) -> Result<Self, Self::Err> {
			let mut s = s.to_string();
			s.make_ascii_lowercase();
			Ok(match s.as_str() {
				"toml" => Self::Toml,
				"json" => Self::Json,
				_ => return Err("must be either 'toml' or 'json'".into()),
			})
		}
	}

	impl Default for ConfigFormat {
		fn default() -> Self {
			ConfigFormat::Toml
		}
	}

	fn read_conf_str(path: Option<&str>) -> Result<String, std::io::Error> {
		let mut conf_str = String::with_capacity(1024);
		if let Some(path) = path {
			println!("Reading config file '{}'", path);
			File::open(path)?.read_to_string(&mut conf_str)?;
		} else {
			std::io::stdin().read_to_string(&mut conf_str)?;
		}
		Ok(conf_str)
	}

	#[cfg(feature = "parse-config")]
	pub(super) fn make_config(opts: &AppOptions) -> Result<Config, Error> {
		fn read_config(conf_str: &str, format: ConfigFormat) -> Result<Config, BoxStdErr> {
			let conf: Config = match format {
				ConfigFormat::Toml => toml::from_str(conf_str)?,
				ConfigFormat::Json => serde_json::from_str(conf_str)?,
			};
			Ok(conf)
		}
		let format = opts.format.unwrap_or_default();
		let conf_str = read_conf_str(opts.config.as_deref())
			.map_err(|e| Error::Input(format!("cannot read config: {}", e).into()))?;
		read_config(&conf_str, format).map_err(Error::Config)
	}
}
#[cfg(feature = "parse-config")]
use parse_config_impl::{make_config, ConfigFormat};

#[derive(Debug, thiserror::Error)]
enum Error {
	#[error("[IO error] {0}")]
	Io(#[from] io::Error),
	#[error("[input] {0}")]
	Input(Cow<'static, str>),
	#[allow(dead_code)]
	#[error("[config] {0}")]
	Config(BoxStdErr),
	#[error("[runtime] {0}")]
	Runtime(BoxStdErr),
}

#[cfg(feature = "parse-url")]
mod parse_url_impl {
	use super::{AppOptions, Config, Cow, Error, FromStr, config};
	use ladder_lib::router;

	/// Make [`Config`] with arguments like `--inbound`, `--outbound`.
	pub(super) fn make_config_from_args(opts: &AppOptions) -> Result<Config, Error> {
		let inbound = {
			let s = opts.inbound.as_ref().ok_or_else(|| {
				Error::Input("`inbound` cannot be empty while `outbound` is not".into())
			})?;
			let url = url::Url::from_str(s).map_err(|e| {
				Error::Input(format!("`inbound` is not a valid URL ({})", e).into())
			})?;
			ladder_lib::server::inbound::Builder::parse_url(&url)
				.map_err(|e| Error::Input(format!("invalid inbound ({})", e).into()))?
		};
		let outbound = {
			let s = opts.outbound.as_ref().ok_or_else(|| {
				Error::Input("`outbound` cannot be empty while `inbound` is not".into())
			})?;
			let url = url::Url::from_str(s).map_err(|e| {
				Error::Input(format!("`outbound` is not a valid URL ({})", e).into())
			})?;
			ladder_lib::server::outbound::Builder::parse_url(&url)
				.map_err(|e| Error::Input(format!("invalid outbound ({})", e).into()))?
		};

		let rules = make_blocklist(opts.block.as_deref())?;
		let level_filter = opts.log.unwrap_or(log::LevelFilter::Warn);
		Ok(Config {
			log: config::Log {
				level: level_filter,
				log_file: opts.log_file.clone().map(Into::into),
			},
			server: ladder_lib::server::Builder {
				inbounds: vec![inbound],
				outbounds: vec![outbound],
				router: router::Builder { rules },
				..Default::default()
			},
		})
	}

	fn make_blocklist(block_str: Option<&str>) -> Result<Vec<router::PlainRule>, Error> {
		const LAN_STR: &str = "$lan";
		const LOCALLOOP_STR: &str = "$localloop";

		let mut dsts: Vec<router::Destination> = Vec::new();
		let block = block_str.map_or_else(
			|| Cow::Owned(format!("{},{}", LAN_STR, LOCALLOOP_STR)),
			Cow::Borrowed,
		);
		
		// Empty blocklist for ""
		if block.is_empty() {
			return Ok(Vec::new());
		}

		for part in block.split(',') {
			match part {
				LAN_STR => dsts.extend(
					Vec::from(router::Cidr::private_networks())
						.into_iter()
						.map(router::Destination::Cidr),
				),
				LOCALLOOP_STR => {
					dsts.push(router::Destination::Cidr(router::Cidr4::LOCALLOOP.into()));
					dsts.push(router::Destination::Cidr(router::Cidr6::LOCALLOOP.into()));
				}
				_ => {
					let ip = std::net::IpAddr::from_str(part).map_err(|_| {
						Error::Input(format!("'{}' is not a valid IP address", part).into())
					})?;
					dsts.push(router::Destination::Ip(ip));
				}
			}
		}
		Ok(if dsts.is_empty() {
			Vec::new()
		} else {
			vec![router::PlainRule {
				dsts,
				outbound_tag: None,
				..Default::default()
			}]
		})
	}
}

#[cfg(feature = "parse-url")]
use parse_url_impl::make_config_from_args;

fn serve(opts: &AppOptions) -> Result<(), Error> {
	let conf = {
		#[cfg(all(feature = "parse-config", feature = "parse-url"))]
		{
			if opts.inbound.is_some() || opts.outbound.is_some() {
				make_config_from_args(opts)?
			} else {
				make_config(opts)?
			}
		}
		#[cfg(all(feature = "parse-config", not(feature = "parse-url")))]
		{
			make_config(opts)?
		}
		#[cfg(all(not(feature = "parse-config"), feature = "parse-url"))]
		{
			make_config_from_args(opts)?
		}
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
		let mut features_msg = String::new();
		for (index, feature) in FEATURES.iter().enumerate() {
			if index != 0 {
				features_msg.push(',');
			}
			features_msg.push_str(feature);
		}
		println!("{}\nFeatures: {}", VERSION, features_msg);
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
		if use_tui && conf.log.log_file.is_none() {
			return Err("cannot use TUI when log file is not set".into());
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
	let is_log_file_none = conf.log_file.is_none();
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
			if is_log_file_none {
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
	if let Some(log_file) = &conf.log_file {
		dispatch.chain(fern::log_file(log_file.as_ref())?).apply()?;
	} else {
		dispatch.chain(std::io::stdout()).apply()?;
	}
	Ok(())
}

mod config {
	use ladder_lib::ServerBuilder;
	use log::LevelFilter;
	use std::borrow::Cow;

	#[cfg_attr(feature = "parse-config", derive(serde::Deserialize))]
	#[cfg_attr(feature = "parse-config", serde(deny_unknown_fields))]
	pub struct Log {
		#[cfg_attr(feature = "parse-config", serde(default = "default_log_level"))]
		pub level: LevelFilter,
		#[cfg_attr(feature = "parse-config", serde(default))]
		#[cfg_attr(feature = "parse-config", serde(rename = "output"))]
		pub log_file: Option<Cow<'static, str>>,
	}

	impl Default for Log {
		fn default() -> Self {
			Log {
				level: default_log_level(),
				log_file: None,
			}
		}
	}

	#[cfg_attr(feature = "parse-config", derive(serde::Deserialize))]
	pub struct Config {
		#[cfg_attr(feature = "parse-config", serde(default))]
		pub log: Log,
		#[cfg_attr(feature = "parse-config", serde(flatten))]
		pub server: ServerBuilder,
	}

	fn default_log_level() -> LevelFilter {
		LevelFilter::Info
	}
}
