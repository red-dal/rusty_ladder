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

use smol_str::SmolStr;

#[derive(Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(rename_all = "lowercase", tag = "type")
)]
pub enum Api {
	None,
	WebApi {
		addr: std::net::SocketAddr,
		secret: SmolStr,
	},
}

impl Default for Api {
	fn default() -> Self {
		Self::None
	}
}
