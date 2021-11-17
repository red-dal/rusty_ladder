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

mod monitor;
pub use monitor::*;

pub mod snapshot;
pub use snapshot::Snapshot;

mod data;
pub use data::{CounterValue, SessionBasicInfo};

pub type Id = u64;
type Tag = SmolStr;

#[cfg(feature = "use-webapi")]
mod webapi;
#[cfg(feature = "use-webapi")]
pub(crate) use webapi::serve_web_api;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "use-webapi", derive(serde::Serialize))]
pub enum Network {
	Tcp,
	Udp,
}

impl Network {
	#[inline]
	pub fn as_str(&self) -> &'static str {
		match self {
			Network::Tcp => "tcp",
			Network::Udp => "udp",
		}
	}
}
