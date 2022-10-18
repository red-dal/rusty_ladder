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

pub struct Log {
	pub level: LevelFilter,
	pub output: Option<LogOutput>,
}

impl Log {
	/// Initialize logger.
	///
	/// DO NOT call this function more than once!
	pub fn init_logger(&self) -> Result<(), BoxStdErr> {
		if let Some(output) = &self.output {
			let time_format =
				time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
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


pub struct Config {
	pub log: Log,
	pub server: ServerBuilder,
}
