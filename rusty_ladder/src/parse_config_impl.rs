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

use super::{Config, Error};
use crate::{
	args::ActionCommons,
	config::{Log, LogOutput},
};
use ladder_lib::ServerBuilder;
use log::LevelFilter;
use std::{ffi::OsStr, io::Read};

fn deserialize_output<'de, D>(deserializer: D) -> Result<Option<LogOutput>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = <&str as serde::Deserialize<'de>>::deserialize(deserializer)?;
	Ok(LogOutput::from_str(s))
}

impl Default for SerdeLog {
	fn default() -> Self {
		Self {
			level: default_log_level(),
			output: default_output(),
		}
	}
}

#[allow(clippy::unnecessary_wraps)]
fn default_output() -> Option<LogOutput> {
	Some(LogOutput::Stdout)
}

fn default_log_level() -> LevelFilter {
	LevelFilter::Info
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerdeLog {
    #[serde(default = "default_log_level")]
	level: LevelFilter,
	#[serde(deserialize_with = "deserialize_output")]
    #[serde(default = "default_output")]
	output: Option<LogOutput>,
}

#[derive(serde::Deserialize)]
pub struct SerdeConfig {
    #[serde(default)]
	pub log: SerdeLog,
    #[serde(flatten)]
	pub server: ServerBuilder,
}

impl From<SerdeConfig> for Config {
	fn from(c: SerdeConfig) -> Self {
		Self {
			log: Log {
				level: c.log.level,
				output: c.log.output,
			},
			server: c.server,
		}
	}
}

#[derive(Clone, Copy)]
enum Format {
	#[cfg(feature = "parse-config-toml")]
	Toml,
	#[cfg(feature = "parse-config-yaml")]
	Yaml,
	#[cfg(feature = "parse-config-json")]
	Json,
}

impl Format {
	fn as_str(self) -> &'static str {
		match self {
			#[cfg(feature = "parse-config-toml")]
			Self::Toml => "toml",
			#[cfg(feature = "parse-config-yaml")]
			Self::Yaml => "yaml",
			#[cfg(feature = "parse-config-json")]
			Self::Json => "json",
		}
	}

	fn from_str(s: &OsStr) -> Option<Self> {
		#[cfg(feature = "parse-config-toml")]
		if s.eq_ignore_ascii_case("toml") {
			return Some(Self::Toml);
		}
		#[cfg(feature = "parse-config-yaml")]
		if s.eq_ignore_ascii_case("yaml") || s.eq_ignore_ascii_case("yml") {
			return Some(Self::Yaml);
		}
		#[cfg(feature = "parse-config-json")]
		if s.eq_ignore_ascii_case("json") {
			return Some(Self::Json);
		}
		None
	}
}

impl Default for Format {
	fn default() -> Self {
		Format::Toml
	}
}

pub(super) fn make_config_from_file(
	format: Option<String>,
	path: &std::path::Path,
	coms: ActionCommons,
) -> Result<Config, Error> {
	let format = if let Some(f) = format {
		Format::from_str(f.as_ref()).ok_or_else(|| Error::input("unknown format"))?
	} else {
		// Determine format from file extension.
		let ext = path.extension();
		ext.and_then(Format::from_str).unwrap_or_default()
	};

	println!(
		"Reading {} config file '{}'...",
		format.as_str(),
		path.to_string_lossy()
	);

	let mut conf_str = String::with_capacity(512);
	std::fs::File::open(&path)
		.map_err(|e| {
			Error::config(format!(
				"cannot open file '{}' ({e})",
				path.to_string_lossy(),
			))
		})?
		.read_to_string(&mut conf_str)
		.map_err(|e| {
			Error::config(format!(
				"cannot read from file '{}' ({e})",
				path.to_string_lossy()
			))
		})?;
	make_config(format, &conf_str, coms)
}

fn make_config(format: Format, conf_str: &str, coms: ActionCommons) -> Result<Config, Error> {
	let conf: SerdeConfig = match format {
		#[cfg(feature = "parse-config-toml")]
		Format::Toml => toml::from_str(conf_str).map_err(Error::config)?,
		#[cfg(feature = "parse-config-yaml")]
		Format::Yaml => serde_yaml::from_str(conf_str).map_err(Error::config)?,
		#[cfg(feature = "parse-config-json")]
		Format::Json => serde_json::from_str(conf_str).map_err(Error::config)?,
	};
	let mut conf: Config = conf.into();
	if coms.use_tui
		&& matches!(&conf.log.output, Some(super::config::LogOutput::Stdout))
		&& coms.log_out.is_none()
	{
		conf.log.output = None;
	} else {
		if let Some(log_out) = coms.log_out {
			conf.log.output = Some(log_out);
		}
		if let Some(log_level) = coms.log {
			conf.log.level = log_level;
		}
	}
	Ok(conf)
}
