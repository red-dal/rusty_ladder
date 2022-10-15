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
use std::{borrow::Cow, str::FromStr};

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum Format {
	Toml,
	Json,
}

impl FromStr for Format {
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

impl Default for Format {
	fn default() -> Self {
		Format::Toml
	}
}

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
