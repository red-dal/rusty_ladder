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

use super::{config::Format, Config, Error};
use crate::args::ActionCommons;

#[cfg(feature = "parse-config")]
pub(super) fn make_config(
	format: Format,
	conf_str: &str,
	coms: ActionCommons,
) -> Result<Config, Error> {
	let mut conf: Config = match format {
		Format::Toml => toml::from_str(conf_str).map_err(|e| Error::Config(e.into()))?,
		Format::Json => serde_json::from_str(conf_str).map_err(|e| Error::Config(e.into()))?,
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
