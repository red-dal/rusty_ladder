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

use super::{config::LogOutput, BoxStdErr};
use clap::{Parser, CommandFactory};

#[cfg(feature = "parse-config")]
use super::config::Format;

#[derive(Parser)]
#[structopt(name = "rusty_ladder")]
pub struct AppOptions {
	/// Enable TUI.
	#[arg(long)]
	tui: bool,

	/// Set the format of the config file. Can be 'toml' (default) or 'json'.
	#[cfg(feature = "parse-config")]
	#[arg(short, long)]
	format: Option<Format>,

	/// Read config from file.
	#[cfg(feature = "parse-config")]
	#[arg(short, long, value_name = "FILE")]
	config: Option<String>,

	/// Print version.
	#[arg(long)]
	version: bool,

	/// Set inbound URL.
	#[cfg(feature = "parse-url")]
	#[arg(short, long, value_name = "URL")]
	inbound: Option<String>,

	/// Set outbound URL.
	#[cfg(feature = "parse-url")]
	#[arg(short, long, name = "URL")]
	outbound: Option<String>,

	#[cfg(feature = "parse-url")]
	/// Block an IP, network (x.x.x.x/xx) or domain.
	#[arg(short, long, value_name = "BLOCKED")]
	block: Vec<String>,

	#[cfg(feature = "parse-url")]
	/// Allow access to LAN and local IPs, which is forbidden by default.
	#[arg(long)]
	allow_lan: bool,

	/// Set the log level. Must be one of ["debug", "info", "warn" (default), "error"]
	#[arg(long, value_name = "LEVEL")]
	log: Option<log::LevelFilter>,

	/// Set the output file for log.
	#[arg(long, name = "FILE")]
	log_out: Option<String>,
}

impl AppOptions {
	pub fn new_from_args() -> Self {
		Self::parse()
	}

	pub fn into_action(self) -> Result<Action, BoxStdErr> {
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
				let mut format = Format::default();
				if let Some(ext) = path.extension() {
					if ext.eq_ignore_ascii_case("toml") {
						format = Format::Toml;
					}
				}
				format
			});
			return Ok(Action::Serve(ServeAction::File { coms, path, format }));
		}

		let mut cmd = Self::command();
		cmd.print_help()?;
		std::process::exit(1);
	}
}

pub enum Action {
	CheckVersion,
	Serve(ServeAction),
}

pub struct ActionCommons {
	pub use_tui: bool,
	pub log: Option<log::LevelFilter>,
	pub log_out: Option<LogOutput>,
}

pub enum ServeAction {
	#[cfg(feature = "parse-config")]
	File {
		coms: ActionCommons,
		path: std::path::PathBuf,
		format: Format,
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
