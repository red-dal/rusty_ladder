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

use super::{Config, Error, FromStr};
use crate::ActionCommons;
use std::borrow::Cow;

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

#[cfg(feature = "parse-config")]
pub(super) fn make_config(
	format: ConfigFormat,
	conf_str: &str,
	coms: ActionCommons,
) -> Result<Config, Error> {
	let mut conf: Config = match format {
		ConfigFormat::Toml => toml::from_str(conf_str).map_err(|e| Error::Config(e.into()))?,
		ConfigFormat::Json => {
			serde_json::from_str(conf_str).map_err(|e| Error::Config(e.into()))?
		}
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
