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
use clap::{ArgGroup, CommandFactory, Parser};

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser)]
#[command(group(
        ArgGroup::new("use_config")
            .conflicts_with("use_url")
            .multiple(true)
))]
#[command(group(
        ArgGroup::new("use_url")
            .multiple(true)
))]
#[command(about = "Rusty proxy client/server.")]
#[command(long_about = "Rusty proxy client/server.

Example:
  rusty_ladder -i URL -o URL [-b ADDR]* [--allow-lan] [--log LEVEL] [--log-out OUT]
  rusty_ladder -c CONFIG -f FORMAT [--log LEVEL] [--log-out OUT]
")]
pub struct AppOptions {
	/// Enable TUI.
	#[arg(long)]
	tui: bool,

	/// Set the format of the config file. Can be 'toml' (default) or 'json'.
	#[cfg(feature = "parse-config")]
	#[arg(short, long)]
	#[arg(group = "use_config")]
	format: Option<String>,

	/// Read config from file.
	#[cfg(feature = "parse-config")]
	#[arg(short, long, value_name = "FILE")]
	#[arg(group = "use_config")]
	config: Option<String>,

	/// Print version.
	#[arg(long)]
	version: bool,

	/// Set inbound URL.
	#[cfg(feature = "parse-url")]
	#[arg(short, long, value_name = "URL")]
	#[arg(group = "use_url")]
	inbound: Option<String>,

	/// Set outbound URL.
	#[cfg(feature = "parse-url")]
	#[arg(short, long, name = "URL")]
	#[arg(group = "use_url")]
	outbound: Option<String>,

	#[cfg(feature = "parse-url")]
	/// Block an IP, network (x.x.x.x/xx) or domain.
	#[arg(short, long, value_name = "BLOCKED")]
	#[arg(group = "use_url")]
	block: Vec<String>,

	#[cfg(feature = "parse-url")]
	/// Allow access to LAN and local IPs, which is forbidden by default.
	#[arg(long)]
	#[arg(group = "use_url")]
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
				return Ok(Action::Serve {
					coms,
					input: ConfigInput::Url {
						in_url,
						out_url,
						block_list: self.block,
						allow_lan: self.allow_lan,
					},
				});
			}
		}

		#[cfg(feature = "parse-config")]
		if let Some(path) = self.config {
			return Ok(Action::Serve {
				coms,
				input: ConfigInput::File {
					path: path.into(),
					format: self.format,
				},
			});
		}

		let mut cmd = Self::command();
		cmd.print_help()?;
		std::process::exit(1);
	}
}

pub enum Action {
	CheckVersion,
	Serve {
		coms: ActionCommons,
		input: ConfigInput,
	},
}

pub struct ActionCommons {
	pub use_tui: bool,
	pub log: Option<log::LevelFilter>,
	pub log_out: Option<LogOutput>,
}

pub enum ConfigInput {
	#[cfg(feature = "parse-config")]
	File {
		path: std::path::PathBuf,
		format: Option<String>,
	},
	#[cfg(feature = "parse-url")]
	Url {
		in_url: String,
		out_url: String,
		block_list: Vec<String>,
		allow_lan: bool,
	},
}
