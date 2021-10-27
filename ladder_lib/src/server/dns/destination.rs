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

use crate::prelude::*;

#[derive(Debug, Clone, Copy)]
enum AddrType {
	Tcp,
	Udp,
	Https,
}

#[derive(Debug)]
pub struct Error {
	atyp: AddrType,
	s: String,
	inner: BoxStdErr,
}

impl Error {
	fn new(atyp: AddrType, s: &str, inner: impl Into<BoxStdErr>) -> Self {
		Self {
			atyp,
			s: s.to_owned(),
			inner: inner.into(),
		}
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let atyp_str = match self.atyp {
			AddrType::Tcp => "TCP",
			AddrType::Udp => "UDP",
			AddrType::Https => "HTTPS",
		};
		write!(
			f,
			"invalid {} address '{}' ({})",
			atyp_str, self.s, self.inner
		)
	}
}

#[derive(Clone, Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(try_from = "String")
)]
pub(super) enum DnsDestination {
	Udp(SocketAddr),
	Tcp(SocketAddr),
	Https(SocksAddr),
}

const HTTPS: &str = "https://";
const TCP: &str = "tcp://";
const UDP: &str = "udp://";

impl FromStr for DnsDestination {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let result = if s.starts_with(HTTPS) {
			let atyp = AddrType::Https;
			let addr_str = s
				.strip_prefix(HTTPS)
				.ok_or_else(|| Error::new(atyp, s, "empty address"))?;
			// Use 443 port if empty.
			let addr =
				SocksAddr::parse_str(addr_str, Some(443)).map_err(|e| Error::new(atyp, s, e))?;
			Self::Https(addr)
		} else if s.starts_with(TCP) {
			let atyp = AddrType::Tcp;
			let addr_str = s
				.strip_prefix(TCP)
				.ok_or_else(|| Error::new(atyp, s, "empty address"))?;
			let addr = addr_str.parse().map_err(|e| Error::new(atyp, s, e))?;
			Self::Tcp(addr)
		} else if s.starts_with(UDP) {
			let atyp = AddrType::Udp;
			let addr_str = s
				.strip_prefix(UDP)
				.ok_or_else(|| Error::new(atyp, s, "empty address"))?;
			let addr = addr_str.parse().map_err(|e| Error::new(atyp, s, e))?;
			Self::Udp(addr)
		} else {
			let atyp = AddrType::Udp;
			let addr_str = s
				.strip_prefix(UDP)
				.ok_or_else(|| Error::new(atyp, s, "empty address"))?;
			let addr = addr_str.parse().map_err(|e| Error::new(atyp, s, e))?;
			Self::Udp(addr)
		};
		Ok(result)
	}
}

impl TryFrom<String> for DnsDestination {
	type Error = Error;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		Self::from_str(value.as_str())
	}
}
