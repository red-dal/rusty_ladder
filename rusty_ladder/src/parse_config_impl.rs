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
use crate::args::ActionCommons;
use std::{ffi::OsStr, io::Read};

#[derive(Clone, Copy)]
enum Format {
	Toml,
	Json,
}

impl Format {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Json => "json",
        }
    }

	fn from_str(s: &OsStr) -> Option<Self> {
		if s.eq_ignore_ascii_case("toml") {
			return Some(Self::Toml);
		}
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

    println!("Reading {} config file '{}'...", format.as_str(), path.to_string_lossy());

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
	let mut conf: Config = match format {
		Format::Toml => toml::from_str(conf_str).map_err(Error::config)?,
		Format::Json => serde_json::from_str(conf_str).map_err(Error::config)?,
	};
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
