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

use std::{num::ParseIntError, str::FromStr};

use rand::thread_rng;
use smol_str::SmolStr;

mod monitor;
pub use monitor::*;

pub mod snapshot;
pub use snapshot::Snapshot;

mod data;
pub use data::{CounterValue, SessionBasicInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "use-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "use-serde", derive(serde::Deserialize))]
pub struct Id(u64);

impl Id {
	#[must_use]
	#[inline]
	pub fn new() -> Self {
		use rand::Rng;
		Self(thread_rng().gen())
	}

	#[must_use]
	#[inline]
	pub fn value(&self) -> u64 {
		self.0
	}
}

impl Default for Id {
	fn default() -> Self {
		Self::new()
	}
}

impl FromStr for Id {
	type Err = ParseIntError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
        u64::from_str_radix(s, 16).map(Self)
	}
}

impl std::fmt::Display for Id {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{:x}", self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::Id;

	#[test]
	fn id_parsing() {
		let id = Id::new();
		assert_eq!(id, id.to_string().parse().unwrap());

		let id = Id::new();
		assert_eq!(id, id.to_string().parse().unwrap());
	}
}

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
	#[must_use]
	pub fn as_str(&self) -> &'static str {
		match self {
			Network::Tcp => "tcp",
			Network::Udp => "udp",
		}
	}
}
