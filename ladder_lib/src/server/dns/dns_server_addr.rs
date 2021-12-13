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
	#[cfg(any(feature = "local-dns-over-openssl", feature = "local-dns-over-rustls"))]
	Tls,
}

impl AddrType {
	fn from_prefix(prefix: &str) -> Option<Self> {
		#[cfg(any(feature = "local-dns-over-openssl", feature = "local-dns-over-rustls"))]
		if prefix.as_bytes().eq_ignore_ascii_case(TLS.as_bytes()) {
			return Some(AddrType::Tls);
		}

		if prefix.as_bytes().eq_ignore_ascii_case(TCP.as_bytes()) {
			Some(AddrType::Tcp)
		} else if prefix.as_bytes().eq_ignore_ascii_case(UDP.as_bytes()) {
			Some(AddrType::Udp)
		} else {
			None
		}
	}
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Error {
	#[error("invalid address '{0}', should be IP:PORT")]
	InvalidSocketAddr(Box<str>),
	#[error("invalid prefix '{0}'")]
	InvalidPrefix(Box<str>),
	#[error("address is too long")]
	TooLong,
	#[error("address is empty")]
	Empty,
	/// A tuple of (addr_str, error_msg)
	#[cfg(any(feature = "local-dns-over-openssl", feature = "local-dns-over-rustls"))]
	#[error("invalid address '{0}' ({1}), should be HOSTNAME:PORT")]
	InvalidSocksAddr(Box<str>, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(try_from = "String")
)]
pub(super) enum DnsServerAddr {
	Udp(SocketAddr),
	Tcp(SocketAddr),
	#[cfg(any(feature = "local-dns-over-openssl", feature = "local-dns-over-rustls"))]
	Tls(SocksAddr),
}

const TCP: &str = "tcp";
const UDP: &str = "udp";
#[cfg(any(feature = "local-dns-over-openssl", feature = "local-dns-over-rustls"))]
const TLS: &str = "tls";

const SEPARATOR: &str = "://";
const MAX_LENGTH: usize = 300;

impl FromStr for DnsServerAddr {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() > MAX_LENGTH {
			return Err(Error::TooLong);
		}
		if s.is_empty() {
			return Err(Error::Empty);
		}

		let (addr_type, addr_str) = if let Some((prefix, addr_str)) = s.split_once(SEPARATOR) {
			let addr_type =
				AddrType::from_prefix(prefix).ok_or_else(|| Error::InvalidPrefix(prefix.into()))?;
			(addr_type, addr_str)
		} else {
			(AddrType::Udp, s)
		};

		match addr_type {
			AddrType::Tcp => SocketAddr::from_str(addr_str)
				.map_err(|_| Error::InvalidSocketAddr(addr_str.into()))
				.map(DnsServerAddr::Tcp),
			AddrType::Udp => SocketAddr::from_str(addr_str)
				.map_err(|_| Error::InvalidSocketAddr(addr_str.into()))
				.map(DnsServerAddr::Udp),
			#[cfg(any(feature = "local-dns-over-openssl", feature = "local-dns-over-rustls"))]
			AddrType::Tls => SocksAddr::from_str(addr_str)
				.map_err(|e| Error::InvalidSocksAddr(addr_str.into(), e.to_string()))
				.map(DnsServerAddr::Tls),
		}
	}
}

impl TryFrom<String> for DnsServerAddr {
	type Error = Error;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		Self::from_str(value.as_str())
	}
}

impl std::fmt::Display for DnsServerAddr {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			DnsServerAddr::Udp(a) => write!(f, "{}{}{}", UDP, SEPARATOR, a),
			DnsServerAddr::Tcp(a) => write!(f, "{}{}{}", TCP, SEPARATOR, a),
			#[cfg(any(feature = "local-dns-over-openssl", feature = "local-dns-over-rustls"))]
			DnsServerAddr::Tls(a) => write!(f, "{}{}{}", TLS, SEPARATOR, a),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_dns_destination_from_str() {
		// Raw IPs
		assert_eq!(
			DnsServerAddr::from_str("0.0.0.0:53").unwrap(),
			DnsServerAddr::Udp(([0, 0, 0, 0], 53).into())
		);
		assert_eq!(
			DnsServerAddr::from_str("255.255.255.255:5353").unwrap(),
			DnsServerAddr::Udp(([255, 255, 255, 255], 5353).into())
		);
		assert_eq!(
			DnsServerAddr::from_str("[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443").unwrap(),
			DnsServerAddr::Udp(SocketAddr::new(
				"2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
				443,
			))
		);
		// UDP
		assert_eq!(
			DnsServerAddr::from_str("udp://0.0.0.0:53").unwrap(),
			DnsServerAddr::Udp(([0, 0, 0, 0], 53).into())
		);
		assert_eq!(
			DnsServerAddr::from_str("udp://255.255.255.255:5353").unwrap(),
			DnsServerAddr::Udp(([255, 255, 255, 255], 5353).into())
		);
		assert_eq!(
			DnsServerAddr::from_str("udp://[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443").unwrap(),
			DnsServerAddr::Udp(SocketAddr::new(
				"2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
				443,
			))
		);
		// TCP
		assert_eq!(
			DnsServerAddr::from_str("tcp://0.0.0.0:53").unwrap(),
			DnsServerAddr::Tcp(([0, 0, 0, 0], 53).into())
		);
		assert_eq!(
			DnsServerAddr::from_str("tcp://255.255.255.255:5353").unwrap(),
			DnsServerAddr::Tcp(([255, 255, 255, 255], 5353).into())
		);
		assert_eq!(
			DnsServerAddr::from_str("tcp://[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443").unwrap(),
			DnsServerAddr::Tcp(SocketAddr::new(
				"2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
				443,
			))
		);
	}

	#[test]
	fn test_dns_destination_from_str_error() {
		assert_eq!(DnsServerAddr::from_str("").unwrap_err(), Error::Empty);
		assert_eq!(
			DnsServerAddr::from_str(&"longlabel.".repeat(100)).unwrap_err(),
			Error::TooLong
		);
		assert_eq!(
			DnsServerAddr::from_str("invalid://127.0.0.1:11111").unwrap_err(),
			Error::InvalidPrefix("invalid".into())
		);
		assert_eq!(
			DnsServerAddr::from_str("invalid2://invalid-address").unwrap_err(),
			Error::InvalidPrefix("invalid2".into())
		);
		assert_eq!(
			DnsServerAddr::from_str("://invalid-address").unwrap_err(),
			Error::InvalidPrefix("".into())
		);
		assert_eq!(
			DnsServerAddr::from_str("tcp://invalid-address").unwrap_err(),
			Error::InvalidSocketAddr("invalid-address".into())
		);
		assert_eq!(
			DnsServerAddr::from_str("udp://invalid-address").unwrap_err(),
			Error::InvalidSocketAddr("invalid-address".into())
		);
	}
}
