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

use args::{ActionCommons, ConfigInput};
// TODO: log to TUI
use config::Config;
use std::{io, sync::Arc};
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

fn main() {
	if let Err(e) = run() {
		eprintln!("{}", e);
		std::process::exit(1);
	}
}

fn run() -> Result<(), BoxStdErr> {
	let action = args::AppOptions::new_from_args().into_action()?;
	match action {
		args::Action::CheckVersion => {
			println!("{}", format_version());
		}
		args::Action::Serve { coms, input } => {
			serve(coms, input)?;
		}
	};
	Ok(())
}

#[cfg(feature = "use-tui")]
mod tui;

#[cfg(feature = "parse-config")]
mod parse_config_impl;
#[cfg(feature = "parse-config")]
use parse_config_impl::make_config_from_file;

#[cfg(feature = "parse-url")]
mod parse_url_impl;
#[cfg(feature = "parse-url")]
use parse_url_impl::make_config_from_args;

mod args;
mod config;

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

fn serve(coms: ActionCommons, input: ConfigInput) -> Result<(), Error> {
	#[cfg(feature = "use-tui")]
	let mut use_tui = false;

	let conf = match input {
		#[cfg(feature = "parse-config")]
		args::ConfigInput::File { path, format } => {
			#[cfg(feature = "use-tui")]
			if coms.use_tui {
				use_tui = true;
			}
			make_config_from_file(format, &path, coms)?
		}

		#[cfg(feature = "parse-url")]
		args::ConfigInput::Url {
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
