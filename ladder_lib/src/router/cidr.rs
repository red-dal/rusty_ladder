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
use std::{
	error::Error,
	fmt::{self, Display, Formatter},
	net::AddrParseError,
	num::ParseIntError,
	str::FromStr,
};

#[derive(Debug)]
pub enum ParseError {
	Format(String),
	Ip((String, AddrParseError)),
	Length((String, ParseIntError)),
}

impl Display for ParseError {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			ParseError::Format(s) => write!(f, "cidr '{}' is invalid", s),
			ParseError::Ip((s, err)) => write!(f, "ip in cidr '{}' is invalid ({})", s, err),
			ParseError::Length((s, err)) => write!(f, "len in cidr '{}' is invalid ({})", s, err),
		}
	}
}

impl Error for ParseError {}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct Cidr4 {
	pub ip: Ipv4Addr,
	pub mask: u32,
}

impl Cidr4 {
	pub const LOCALLOOP: Self = Self::from_ip(Ipv4Addr::new(127, 0, 0, 0), 8);

	#[must_use]
	pub const fn from_ip(ip: Ipv4Addr, length: u8) -> Self {
		debug_assert!(length <= 32);
		let mask = (!0 as u32) << (32 - length);
		Cidr4 { ip, mask }
	}

	#[must_use]
	pub fn new(ip: impl Into<Ipv4Addr>, length: u8) -> Self {
		Self::from_ip(ip.into(), length)
	}

	#[must_use]
	pub fn contains(&self, ip: Ipv4Addr) -> bool {
		let other_ip_data = u32::from(ip) & self.mask;
		let ip_data = u32::from(self.ip) & self.mask;
		ip_data == other_ip_data
	}
}

impl Display for Cidr4 {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}/{}", self.ip, self.mask)
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct Cidr6 {
	pub ip: Ipv6Addr,
	pub mask: u128,
}

impl Cidr6 {
	pub const LOCALLOOP: Self = Self::from_ip(Ipv6Addr::LOCALHOST, 128);

	#[must_use]
	pub const fn from_ip(ip: Ipv6Addr, length: u8) -> Self {
		debug_assert!(length <= 128);
		let mask = (!0 as u128) << (128 - length);
		Cidr6 { ip, mask }
	}

	pub fn new(ip: impl Into<Ipv6Addr>, length: u8) -> Self {
		Self::from_ip(ip.into(), length)
	}

	#[must_use]
	pub fn contains(&self, ip: &Ipv6Addr) -> bool {
		let other_ip_data = u128::from(*ip) & self.mask;
		let ip_data = u128::from(self.ip) & self.mask;
		ip_data == other_ip_data
	}
}

impl Display for Cidr6 {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}/{}", self.ip, self.mask)
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::module_name_repetitions)]
pub enum Cidr {
	V4(Cidr4),
	V6(Cidr6),
}

impl Display for Cidr {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::V4(cidr) => cidr.fmt(f),
			Self::V6(cidr) => cidr.fmt(f),
		}
	}
}

impl Cidr {
	/// Returns true if an ip address is contained in the network. Returns false otherwise.
	#[must_use]
	pub fn match_ip(&self, ip: &IpAddr) -> bool {
		match self {
			Self::V4(cidr) => match ip {
				IpAddr::V4(ip) => cidr.contains(*ip),
				IpAddr::V6(_) => false,
			},
			Self::V6(cidr) => match ip {
				IpAddr::V6(ip) => cidr.contains(ip),
				IpAddr::V4(_) => false,
			},
		}
	}

	#[inline]
	#[must_use]
	pub fn from_ip(ip: IpAddr, len: u8) -> Self {
		match ip {
			IpAddr::V4(ip) => Cidr::from_ipv4(ip, len),
			IpAddr::V6(ip) => Cidr::from_ipv6(ip, len),
		}
	}

	#[inline]
	#[must_use]
	pub fn from_ipv4(ip: Ipv4Addr, len: u8) -> Self {
		Cidr::V4(Cidr4::from_ip(ip, len))
	}

	#[inline]
	#[must_use]
	pub fn from_ipv6(ip: Ipv6Addr, len: u8) -> Self {
		Cidr::V6(Cidr6::from_ip(ip, len))
	}

	/// Return a list of private networks. 
	/// This does not include local loop.
	/// 
	/// Read more at <https://en.wikipedia.org/wiki/Reserved_IP_addresses>
	#[must_use]
	pub fn private_networks() -> [Self; 5] {
		[
			// IPv4
			Cidr4::new([10, 0, 0, 0], 8).into(),
			Cidr4::new([100, 64, 0, 0], 10).into(),
			Cidr4::new([172, 16, 0, 0], 12).into(),
			Cidr4::new([192, 168, 0, 0], 16).into(),
			// IPv6
			Cidr6::new([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10).into(),
		]
	}
}

impl FromStr for Cidr {
	type Err = ParseError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let sep_pos = s
			.find('/')
			.ok_or_else(|| ParseError::Format(s.to_owned()))?;
		let (ip_str, len_str) = s.split_at(sep_pos);
		if len_str.len() <= 1 {
			return Err(ParseError::Format(s.to_owned()));
		}
		let len_str = &len_str[1..];
		let ip = IpAddr::from_str(ip_str).map_err(|err| ParseError::Ip((s.to_owned(), err)))?;
		let length =
			u8::from_str(len_str).map_err(|err| ParseError::Length((s.to_owned(), err)))?;
		Ok(Self::from_ip(ip, length))
	}
}

impl From<Cidr4> for Cidr {
	fn from(cidr: Cidr4) -> Self {
		Self::V4(cidr)
	}
}

impl From<Cidr6> for Cidr {
	fn from(cidr: Cidr6) -> Self {
		Self::V6(cidr)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_cidr() {
		let data = "192.168.0.2/24";
		let cidr = Cidr::from_str(data).unwrap();
		println!("{:?}", cidr);
		match &cidr {
			Cidr::V4(cidr) => {
				assert_eq!(cidr.ip, Ipv4Addr::from_str("192.168.0.2").unwrap());
				assert_eq!(cidr.mask, 0xffff_ff00);
			}
			Cidr::V6(_) => {
				panic!("{} is not ipv4 cidr!", data);
			}
		}
		assert_eq!(
			cidr.match_ip(&IpAddr::from_str("192.168.1.0").unwrap()),
			false
		);
		assert_eq!(
			cidr.match_ip(&IpAddr::from_str("192.168.0.0").unwrap()),
			true
		);
		assert_eq!(
			cidr.match_ip(&IpAddr::from_str("192.168.0.55").unwrap()),
			true
		);
	}

	#[test]
	fn test_cidr4() {
		let ip = Ipv4Addr::from_str("127.0.0.1").unwrap();
		let cidr = Cidr4::from_ip(ip, 16);
		println!("{:?}", cidr);
		assert_eq!(cidr.ip, Ipv4Addr::from_str("127.0.0.1").unwrap());
		assert_eq!(cidr.mask, 0xffff_0000);
		assert!(cidr.contains(ip));
		assert!(!cidr.contains(Ipv4Addr::new(1, 1, 1, 1)));
		assert!(cidr.contains(Ipv4Addr::from_str("127.0.1.0").unwrap()));
	}

	#[test]
	fn test_cidr6() {
		let ip = Ipv6Addr::from_str("2001:0db8:0123:4567:89ab:1234:1234:5678").unwrap();
		let cidr = Cidr6::from_ip(ip, 96);
		println!("{:?}", cidr);
		assert_eq!(
			cidr.ip,
			Ipv6Addr::from_str("2001:0db8:0123:4567:89ab:1234:1234:5678").unwrap()
		);
		assert_eq!(cidr.mask, (!0 as u128) << 32);
		assert!(cidr.contains(&ip));
		assert!(cidr.contains(&Ipv6Addr::from_str("2001:0db8:0123:4567:89ab:1234:1234::").unwrap()));
		assert!(!cidr.contains(&Ipv6Addr::from_str("2001:0db8:0123::").unwrap()));
	}
}
