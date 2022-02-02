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

use crate::{prelude::*, utils::ReadInt};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use smol_str::SmolStr;
use std::{
	borrow::Borrow,
	fmt::{self, Display},
	io,
	num::NonZeroU16,
	str::FromStr,
	string,
};

const EMPTY_STRING: &str = "empty string";

// See more at <https://tools.ietf.org/html/rfc1928>
#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum AddrType {
	Ipv4 = 1_u8,
	Name = 3_u8,
	Ipv6 = 4_u8,
}

impl AddrType {
	#[inline]
	#[must_use]
	pub const fn val(self) -> u8 {
		self as u8
	}
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
	#[error("string is not utf8 ({0})")]
	StringNotUtf8(string::FromUtf8Error),
	#[error("str is not utf8 ({0})")]
	StrNotUtf8(std::str::Utf8Error),
	#[error("unknown address type {0}")]
	UnknownAddressType(u8),
	#[error("invalid domain ({0})")]
	InvalidDomain(BoxStdErr),
	#[error("invalid port ({0})")]
	InvalidPort(BoxStdErr),
	#[error("invalid address ({0})")]
	InvalidAddress(BoxStdErr),
	#[error("buffer of {buf_len:?} bytes is too small, which required at least {exp_len:?} bytes")]
	BufferTooSmall { buf_len: usize, exp_len: usize },
	#[error("IO error ({0})")]
	Io(#[from] io::Error),
}

impl ReadError {
	#[must_use]
	pub fn into_io_err(self) -> io::Error {
		if let Self::Io(e) = self {
			e
		} else {
			io::Error::new(io::ErrorKind::InvalidData, self)
		}
	}
}

// -------------------------------------------------------
//                     SocksDestination
// -------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocksDestination {
	/// Must be a valid domain name.
	Name(DomainName),
	Ip(IpAddr),
}

impl SocksDestination {
	#[inline]
	#[must_use]
	/// Create a new `SocksDestination` from [`IpAddr`].
	pub fn new_ip(ip: impl Into<IpAddr>) -> Self {
		Self::Ip(ip.into())
	}

	#[inline]
	/// Create a new `SocksDestination` from [`str`].
	/// # Errors
	/// Return a [`ReadError`] if `value` is not a valid domain name.
	pub fn new_domain(value: impl AsRef<str>) -> Result<Self, ReadError> {
		DomainName::from_str(value.as_ref()).map(SocksDestination::Name)
	}

	#[inline]
	#[must_use]
	pub fn atyp(&self) -> AddrType {
		match self {
			SocksDestination::Name(_) => AddrType::Name,
			SocksDestination::Ip(IpAddr::V4(_)) => AddrType::Ipv4,
			SocksDestination::Ip(IpAddr::V6(_)) => AddrType::Ipv6,
		}
	}

	#[inline]
	#[must_use]
	pub fn to_str(&self) -> Cow<'_, str> {
		#[cfg(debug_assertions)]
		if let Self::Name(name) = self {
			debug_assert!(!name.is_empty(), "SocksDestination name cannot be empty!");
		}

		match self {
			SocksDestination::Name(name) => Cow::Borrowed(name.as_str()),
			SocksDestination::Ip(ip) => Cow::Owned(ip.to_string()),
		}
	}

	// ***Deserialize

	/// Creates a [`SocksDestination`] from address type `atyp` and byte stream `r`.
	///
	/// The format for each address type are as following:
	/// - [`AddrType::Ipv4`]: | 4 bytes |
	/// - [`AddrType::Ipv4`]: | 16 bytes |
	/// - [`AddrType::Name`]: | n, 1 byte | n bytes |
	///
	///
	/// # Errors
	///
	/// [`ReadError`] will be returned if error occurred.
	pub fn read_from_atyp<R>(r: &mut R, atyp: AddrType) -> Result<Self, ReadError>
	where
		R: std::io::Read,
	{
		Ok(match atyp {
			AddrType::Ipv4 => {
				let mut buf = [0_u8; 4];
				r.read_exact(&mut buf)?;
				Ipv4Addr::from(buf).into()
			}
			AddrType::Ipv6 => {
				let mut buf = [0_u8; 16];
				r.read_exact(&mut buf)?;
				Ipv6Addr::from(buf).into()
			}
			AddrType::Name => {
				let mut len = [0_u8; 1];
				r.read_exact(&mut len)?;
				let len = len[0];
				if len == 0 {
					return Err(ReadError::InvalidDomain(EMPTY_STRING.into()));
				}
				// Domain length is a u8, which will never be larger than 256.
				let mut buffer = [0_u8; 256];
				let buffer = &mut buffer[..len as usize];
				r.read_exact(buffer)?;
				let name = std::str::from_utf8(buffer).map_err(ReadError::StrNotUtf8)?;
				SocksDestination::Name(DomainName(name.into()))
			}
		})
	}

	/// This is the async version of [`Self::read_from_atyp`].
	///
	/// # Errors
	/// This function returns the same error as [`Self::read_from_atyp`].
	///
	/// [`Self::read_from_atyp`]: crate::utils::socks_addr::SocksDestination::read_from_atyp()
	pub async fn async_read_from_atyp(
		r: &mut (impl AsyncRead + Unpin),
		atyp: AddrType,
	) -> Result<Self, ReadError> {
		Ok(match atyp {
			AddrType::Ipv4 => Ipv4Addr::from(r.read_u32().await?).into(),
			AddrType::Ipv6 => Ipv6Addr::from(r.read_u128().await?).into(),
			AddrType::Name => {
				let len = r.read_u8().await?;
				if len == 0 {
					return Err(ReadError::InvalidDomain(EMPTY_STRING.into()));
				}
				// Domain length is a u8, which will never be larger than 256.
				let mut buffer = [0_u8; 256];
				let buffer = &mut buffer[..len as usize];
				r.read_exact(buffer).await?;
				let name = std::str::from_utf8(buffer).map_err(ReadError::StrNotUtf8)?;

				SocksDestination::from_str(name)?
			}
		})
	}

	// ***Serialize

	pub fn write_to_no_atyp(&self, buf: &mut impl BufMut) {
		match self {
			SocksDestination::Name(name) => {
				buf.put_u8(name.len());
				buf.put(name.as_bytes());
			}
			SocksDestination::Ip(ip) => match ip {
				IpAddr::V4(ipv4) => {
					buf.put(&ipv4.octets()[..]);
				}
				IpAddr::V6(ipv6) => {
					buf.put(&ipv6.octets()[..]);
				}
			},
		}
	}

	#[inline]
	#[must_use]
	/// Get the minimal length of buffer needed to store the serialized data.
	pub fn serialized_len_atyp(&self) -> usize {
		// ATYP (1 byte) + ADDR
		1 + match self {
			SocksDestination::Ip(ip) => match ip {
				IpAddr::V4(_) => 4,
				IpAddr::V6(_) => 16,
			},
			// N (1 byte) + NAME (N bytes)
			SocksDestination::Name(name) => 1 + name.len() as usize,
		}
	}
}

// --- Traits ---

impl FromStr for SocksDestination {
	type Err = ReadError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.is_empty() {
			return Err(ReadError::InvalidDomain(EMPTY_STRING.into()));
		}
		let _ip_err = match IpAddr::from_str(s) {
			Ok(ip) => return Ok(Self::Ip(ip)),
			Err(e) => e,
		};
		DomainName::from_str(s).map(Self::Name)
	}
}

impl From<DomainName> for SocksDestination {
	#[inline]
	fn from(domain: DomainName) -> Self {
		Self::Name(domain)
	}
}

impl From<Ipv4Addr> for SocksDestination {
	#[inline]
	fn from(ip: Ipv4Addr) -> Self {
		Self::Ip(ip.into())
	}
}

impl From<Ipv6Addr> for SocksDestination {
	#[inline]
	fn from(ip: Ipv6Addr) -> Self {
		Self::Ip(ip.into())
	}
}

impl From<IpAddr> for SocksDestination {
	#[inline]
	fn from(ip: IpAddr) -> Self {
		Self::Ip(ip)
	}
}

impl Display for SocksDestination {
	#[inline]
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Ip(ip) => ip.fmt(f),
			Self::Name(name) => name.fmt(f),
		}
	}
}

// -------------------------------------------------------
//                       SocksAddr
// -------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SocksAddr {
	pub dest: SocksDestination,
	pub port: u16,
}

impl SocksAddr {
	#[inline]
	#[must_use]
	pub fn new(dest: SocksDestination, port: u16) -> Self {
		Self { dest, port }
	}

	// ***Deserialize

	/// Creates a [`SocksAddr`] from byte stream `r`.
	///
	/// This function will try to read in the following format:
	/// ```not_rust
	/// +------+----------------+----------------+
	/// | ATYP |  Destination   |     Port       |
	/// +------+----------------+----------------+
	/// | u8   | various bytes  |   2 bytes      |
	/// |      |                | big endian u16 |
	/// +------+----------------+----------------+
	/// ```
	///
	/// Reading will be done in the following steps:
	///
	/// 1) 1 byte will be read to determined the address type `atyp`. See more at [`AddrType`].
	/// 2) a [`SocksDestination`] will be read using `atyp`
	///    ( See more at [`SocksDestination::read_from_atyp`] ).
	/// 3) 2 bytes will be read into a u16 as port.
	///
	/// By default [`AddrType`]'s value will be used to determined address type.
	/// For custom values, use [`SocksDestination::read_from_atyp`] manually.
	///
	/// # Errors
	///
	/// If there is any error, an [`ReadError`] will be returned.
	///
	///[`SocksDestination::read_from_atyp`]: SocksDestination::read_from_atyp()
	pub fn read_from<R>(r: &mut R) -> Result<Self, ReadError>
	where
		R: std::io::Read,
	{
		let atyp_num = r.read_u8()?;
		let atyp =
			AddrType::try_from(atyp_num).map_err(|_| ReadError::UnknownAddressType(atyp_num))?;
		let dest = SocksDestination::read_from_atyp(r, atyp)?;
		let port = r.read_u16()?;
		Ok(Self::new(dest, port))
	}

	/// This is a helper function for reading from bytes instead of a stream.
	///
	/// It is the same as `Self::read_from(std::io::Cursor::new(buf))`.
	///
	/// # Errors
	///
	/// This function returns the same error as [`Self::read_from`].
	#[inline]
	pub fn read_from_bytes(buf: &[u8]) -> Result<(Self, NonZeroU16), ReadError> {
		let mut cur = std::io::Cursor::new(buf);
		let addr = Self::read_from(&mut cur)?;
		let n = u16::try_from(cur.position()).expect("Read more bytes than u16 can hold, wtf");
		let n = NonZeroU16::new(n).expect("0 byte is read while reading SocksAddr");
		Ok((addr, n))
	}

	/// This is the async version of [`Self::read_from`].
	///
	/// # Errors
	///
	/// This function returns the same error as [`Self::read_from`].
	pub async fn async_read_from<R>(r: &mut R) -> Result<Self, ReadError>
	where
		R: AsyncRead + Unpin,
	{
		let atyp_num = r.read_u8().await?;
		let atyp =
			AddrType::try_from(atyp_num).map_err(|_| ReadError::UnknownAddressType(atyp_num))?;
		let dest: SocksDestination = SocksDestination::async_read_from_atyp(r, atyp).await?;
		let port = r.read_u16().await?;
		Ok(Self::new(dest, port))
	}

	// ***Serialize

	/// Return the number of bytes it will take to store the seralized address.
	#[inline]
	#[must_use]
	pub fn serialized_len_atyp(&self) -> usize {
		// length of port(u16) plus the other parts
		self.dest.serialized_len_atyp() + 2
	}

	/// Write the address into `buf` in [SOCKS5 address format].
	///
	/// Data will be written into `buf` in the following format:
	/// ```not_rust
	/// +------+----------------+----------------+
	/// | ATYP |  Destination   |     Port       |
	/// +------+----------------+----------------+
	/// | u8   | various bytes  |   2 bytes      |
	/// |      |                | big endian u16 |
	/// +------+----------------+----------------+
	/// ```
	/// [`AddrType`]'s value will be used in ATYP field.
	/// If you want to use custom ATYP value or serialize in other format,
	/// write each parts into `buf` manually.
	///
	/// [SOCKS5 address format]: https://tools.ietf.org/html/rfc1928#section-5
	#[inline]
	pub fn write_to<B: BufMut>(&self, buf: &mut B) {
		buf.put_u8(self.dest.atyp() as u8);
		self.dest.write_to_no_atyp(buf);
		buf.put_u16(self.port);
	}

	/// Parse an string `s` with an optional default port `default_port` and returns an address.
	///
	/// If `default_port` is [`None`],
	/// string like 'domain:port' is acceptable.
	///
	/// If `default_port` is not [`None`],
	/// string like 'domain:port' and 'domain' is acceptable.
	/// When the port section is not in string `s`,
	/// the value in `default_port` will be used instead.
	///
	/// # Errors
	///
	/// If `default_port` is [`None`] and there are no port in `s`, or the string is invalid,
	/// a [`ReadError`] will be returned.
	pub fn parse_str(s: &str, default_port: Option<u16>) -> Result<Self, ReadError> {
		if let Ok(addr) = s.parse::<SocketAddr>() {
			return Ok(addr.into());
		}
		if s.is_empty() {
			return Err(ReadError::InvalidAddress(EMPTY_STRING.into()));
		}
		let mut parts = s.split_terminator(':');

		let dest = {
			let host_str = parts
				.next()
				.ok_or_else(|| ReadError::InvalidAddress("missing domain/IP".into()))?;
			SocksDestination::from_str(host_str)?
		};

		let port = {
			let port_str = parts.next();
			if let Some(port_str) = port_str {
				if port_str.is_empty() {
					return Err(ReadError::InvalidPort(EMPTY_STRING.into()));
				}
				port_str
					.parse::<u16>()
					.map_err(|err| ReadError::InvalidPort(err.into()))?
			} else {
				// There are no port in the str.
				default_port.ok_or_else(|| ReadError::InvalidAddress("missing port".into()))?
			}
		};

		Ok(Self { dest, port })
	}
}

// --- Traits ---

impl FromStr for SocksAddr {
	type Err = ReadError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::parse_str(s, None)
	}
}

impl Display for SocksAddr {
	#[inline]
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match &self.dest {
			SocksDestination::Name(name) => write!(f, "{}:{}", name, self.port),
			SocksDestination::Ip(ip) => SocketAddr::new(*ip, self.port).fmt(f),
		}
	}
}

impl From<SocketAddr> for SocksAddr {
	#[inline]
	fn from(addr: SocketAddr) -> Self {
		Self {
			dest: addr.ip().into(),
			port: addr.port(),
		}
	}
}

impl From<(SocksDestination, u16)> for SocksAddr {
	#[inline]
	fn from((dest, port): (SocksDestination, u16)) -> Self {
		Self { dest, port }
	}
}

impl From<(IpAddr, u16)> for SocksAddr {
	#[inline]
	fn from((ip, port): (IpAddr, u16)) -> Self {
		Self {
			dest: SocksDestination::Ip(ip),
			port,
		}
	}
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
	#[inline]
	fn from((ip, port): (Ipv4Addr, u16)) -> Self {
		Self {
			dest: SocksDestination::Ip(ip.into()),
			port,
		}
	}
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
	#[inline]
	fn from((ip, port): (Ipv6Addr, u16)) -> Self {
		Self {
			dest: SocksDestination::Ip(ip.into()),
			port,
		}
	}
}

#[cfg(feature = "serde")]
mod serde_internal {
	use super::SocksAddr;
	use serde::{de::Visitor, Deserialize, Serialize};
	use std::{
		fmt::{self, Formatter},
		str::FromStr,
	};

	impl<'de> Deserialize<'de> for SocksAddr {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: serde::Deserializer<'de>,
		{
			struct AddressVisitor;

			impl<'de> Visitor<'de> for AddressVisitor {
				type Value = SocksAddr;

				fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
					formatter.write_str("[IP/Domain]:[Port]")
				}

				fn visit_str<E>(self, value: &str) -> Result<SocksAddr, E>
				where
					E: serde::de::Error,
				{
					SocksAddr::from_str(value).map_err(serde::de::Error::custom)
				}
			}

			deserializer.deserialize_str(AddressVisitor)
		}
	}

	impl<'de> Serialize for SocksAddr {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: serde::Serializer,
		{
			let val = self.to_string();
			serializer.serialize_str(&val)
		}
	}
}

// -------------------------------------------------------
//                     DomainName
// -------------------------------------------------------

/// A domain string that's guaranteed to be at most 255 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct DomainName(SmolStr);

impl DomainName {
	#[inline]
	#[must_use]
	pub fn as_str(&self) -> &str {
		self.0.as_str()
	}

	#[allow(clippy::cast_possible_truncation)]
	#[inline]
	#[must_use]
	pub fn len(&self) -> u8 {
		// Length is guaranteed to be u8
		self.0.len() as u8
	}

	#[inline]
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl std::str::FromStr for DomainName {
	type Err = ReadError;

	fn from_str(v: &str) -> Result<Self, ReadError> {
		if v.is_empty() {
			return Err(ReadError::InvalidDomain(EMPTY_STRING.into()));
		}
		if v.len() > 256 {
			return Err(ReadError::InvalidDomain("too long".into()));
		}
		// Remove the final dot '.' if possible.
		let v = v.strip_suffix('.').unwrap_or(v);
		let name =
			idna::domain_to_ascii_strict(v).map_err(|e| ReadError::InvalidDomain(e.into()))?;
		Ok(Self(SmolStr::new(&name)))
	}
}

impl std::ops::Deref for DomainName {
	type Target = SmolStr;

	#[inline]
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl AsRef<str> for DomainName {
	#[inline]
	fn as_ref(&self) -> &str {
		self.0.as_ref()
	}
}

impl AsRef<SmolStr> for DomainName {
	#[inline]
	fn as_ref(&self) -> &SmolStr {
		&self.0
	}
}

impl Borrow<str> for DomainName {
	#[inline]
	fn borrow(&self) -> &str {
		self.0.as_str()
	}
}

impl Borrow<SmolStr> for DomainName {
	#[inline]
	fn borrow(&self) -> &SmolStr {
		&self.0
	}
}

impl Display for DomainName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		Display::fmt(&self.0, f)
	}
}

// -------------------------------------------------------
//                          Tests
// -------------------------------------------------------

#[cfg(test)]
mod dest_tests {
	use super::*;
	use lazy_static::lazy_static;

	const TEST_IPV4: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
	const TEST_IPV6: Ipv6Addr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
	lazy_static! {
		static ref TEST_DOMAIN: DomainName = DomainName::from_str("hello.world").unwrap();
	}

	#[test]
	fn test_dest_write_to() {
		let inputs = [
			SocksDestination::from(TEST_IPV4),
			SocksDestination::from(TEST_IPV6),
			SocksDestination::from(TEST_DOMAIN.clone()),
		];
		let expected_results = vec![
			{
				let mut buf = vec![];
				buf.put_slice(&TEST_IPV4.octets());
				buf
			},
			{
				let mut buf = vec![];
				buf.put_slice(&TEST_IPV6.octets());
				buf
			},
			{
				let name = TEST_DOMAIN.as_str();
				let mut buf = vec![];
				buf.put_u8(name.as_bytes().len() as u8);
				buf.put_slice(name.as_bytes());
				buf
			},
		];
		for (input, expected) in inputs.iter().zip(expected_results.iter()) {
			let mut buf = Vec::new();
			input.write_to_no_atyp(&mut buf);
			assert_eq!(&buf, expected, "cannot write {:?} to {:?}", input, expected);
			assert_eq!(
				buf.len(),
				input.serialized_len_atyp() - 1,
				"cannot write {:?} to {:?}",
				input,
				expected
			);
		}
	}

	#[test]
	fn test_dest_async_read_from() {
		let inputs = vec![
			{
				let mut buf = vec![];
				buf.put_slice(&TEST_IPV4.octets());
				(buf, AddrType::Ipv4)
			},
			{
				let mut buf = vec![];
				buf.put_slice(&TEST_IPV6.octets());
				(buf, AddrType::Ipv6)
			},
			{
				let name = TEST_DOMAIN.as_str();
				let mut buf = vec![];
				buf.put_u8(name.as_bytes().len() as u8);
				buf.put_slice(name.as_bytes());
				(buf, AddrType::Name)
			},
		];
		let expected_results = [
			SocksDestination::from(TEST_IPV4),
			SocksDestination::from(TEST_IPV6),
			SocksDestination::from(TEST_DOMAIN.clone()),
		];
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			for ((input, atyp), expected) in inputs.iter().zip(expected_results.iter()) {
				let result = SocksDestination::async_read_from_atyp(&mut input.as_slice(), *atyp)
					.await
					.unwrap();
				assert_eq!(
					&result, expected,
					"cannot parse bytes {:?} to {:?}",
					input, expected
				);
				assert_eq!(
					result.serialized_len_atyp() - 1,
					input.len(),
					"cannot parse bytes {:?} to {:?}",
					input,
					expected
				);
			}
		});
	}

	#[test]
	fn test_dest_read_from() {
		let inputs = vec![
			{
				let mut buf = vec![];
				buf.put_slice(&TEST_IPV4.octets());
				(buf, AddrType::Ipv4)
			},
			{
				let mut buf = vec![];
				buf.put_slice(&TEST_IPV6.octets());
				(buf, AddrType::Ipv6)
			},
			{
				let name = TEST_DOMAIN.as_str();
				let mut buf = vec![];
				buf.put_u8(name.as_bytes().len() as u8);
				buf.put_slice(name.as_bytes());
				(buf, AddrType::Name)
			},
		];
		let expected_results = [
			SocksDestination::from(TEST_IPV4),
			SocksDestination::from(TEST_IPV6),
			SocksDestination::from(TEST_DOMAIN.clone()),
		];
		for ((input, atyp), expected) in inputs.iter().zip(expected_results.iter()) {
			let result = SocksDestination::read_from_atyp(&mut input.as_slice(), *atyp).unwrap();
			assert_eq!(
				&result, expected,
				"cannot parse {:?} to {:?}",
				input, expected
			);
			assert_eq!(
				result.serialized_len_atyp() - 1,
				input.len(),
				"cannot parse {:?} to {:?}",
				input,
				expected
			);
		}
	}

	#[test]
	fn test_dest_from_str_ipv4() {
		let inputs = [
			TEST_IPV4.to_string(),
			TEST_IPV6.to_string(),
			TEST_DOMAIN.as_str().to_string(),
		];
		let expected_results = [
			SocksDestination::from(TEST_IPV4),
			SocksDestination::from(TEST_IPV6),
			SocksDestination::from(TEST_DOMAIN.clone()),
		];
		for (input, expected) in inputs.iter().zip(expected_results.iter()) {
			assert_eq!(
				&SocksDestination::from_str(input).unwrap(),
				expected,
				"from_str failed on input '{}'",
				input
			);
		}
	}

	#[test]
	fn test_dest_from_str_error() {
		assert!(
			matches!(
				SocksDestination::from_str("").unwrap_err(),
				ReadError::InvalidDomain(_)
			),
			"empty string should not be accepted"
		);
		assert!(
			matches!(
				SocksDestination::from_str("bad.host_name").unwrap_err(),
				ReadError::InvalidDomain(_)
			),
			"'_' should not be accepted"
		);
		assert!(
			matches!(
				SocksDestination::from_str("bad*.domain").unwrap_err(),
				ReadError::InvalidDomain(_)
			),
			"'*' should not be accepted"
		);
	}

	#[test]
	fn test_dest_display() {
		let inputs = [
			SocksDestination::from(TEST_IPV4),
			SocksDestination::from(TEST_IPV6),
			SocksDestination::from(TEST_DOMAIN.clone()),
		];
		let expected_results = [
			TEST_IPV4.to_string(),
			TEST_IPV6.to_string(),
			TEST_DOMAIN.to_string(),
		];
		for (input, expected) in inputs.iter().zip(expected_results.iter()) {
			assert_eq!(
				&input.to_string(),
				expected,
				"{:?} to_string != '{}'",
				input,
				expected
			);
		}
	}

	#[test]
	fn test_dest_to_str() {
		let inputs = [
			SocksDestination::from(TEST_IPV4),
			SocksDestination::from(TEST_IPV6),
			SocksDestination::from(TEST_DOMAIN.clone()),
		];
		let expected_results = [
			Cow::Owned(TEST_IPV4.to_string()),
			Cow::Owned(TEST_IPV6.to_string()),
			Cow::Borrowed(TEST_DOMAIN.as_str()),
		];
		for (input, expected) in inputs.iter().zip(expected_results.iter()) {
			assert_eq!(
				&input.to_str(),
				expected,
				"{:?} to_string != '{}'",
				input,
				expected
			);
		}
	}
}

#[cfg(test)]
mod addr_tests {
	use super::*;
	use lazy_static::lazy_static;
	use std::net::Ipv4Addr;

	const TEST_IPV4: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
	const TEST_IPV6: Ipv6Addr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
	const TEST_PORT: u16 = 54321;
	lazy_static! {
		static ref TEST_DOMAIN: DomainName = DomainName::from_str("hello.world").unwrap();
	}

	#[test]
	fn test_addr_read_from_v4() {
		let inputs = [
			{
				let mut input = vec![];
				input.put_u8(AddrType::Ipv4.val());
				input.put_slice(&TEST_IPV4.octets());
				input.put_u16(TEST_PORT);
				input
			},
			{
				let mut input = vec![];
				input.put_u8(AddrType::Ipv6.val());
				input.put_slice(&TEST_IPV6.octets());
				input.put_u16(TEST_PORT);
				input
			},
			{
				let mut input = vec![];
				input.put_u8(AddrType::Name as u8);
				input.put_u8(TEST_DOMAIN.len());
				input.put_slice(TEST_DOMAIN.as_bytes());
				input.put_u16(TEST_PORT);
				input
			},
		];

		let expected_results = [
			SocksAddr::new(TEST_IPV4.into(), TEST_PORT),
			SocksAddr::new(TEST_IPV6.into(), TEST_PORT),
			SocksAddr::new(TEST_DOMAIN.clone().into(), TEST_PORT),
		];

		for (input, expected) in inputs.iter().zip(expected_results.iter()) {
			let result = SocksAddr::read_from(&mut input.as_slice()).unwrap();
			assert_eq!(
				&result, expected,
				"cannot read {:?} into {:?}",
				input, expected
			);
			assert_eq!(
				result.serialized_len_atyp(),
				input.len(),
				"cannot read {:?} into {:?}",
				input,
				expected
			);
		}
	}

	#[test]
	fn test_addr_from_str_ipv4() {
		let val = format!("{}", SocketAddr::new(TEST_IPV4.into(), TEST_PORT));
		assert_eq!(
			SocksAddr::from_str(&val).unwrap(),
			SocksAddr::new(TEST_IPV4.into(), TEST_PORT)
		)
	}

	#[test]
	fn test_addr_from_str_ipv6() {
		let val = format!("{}", SocketAddr::new(TEST_IPV6.into(), TEST_PORT));
		assert_eq!(
			SocksAddr::from_str(&val).unwrap(),
			SocksAddr::new(TEST_IPV6.into(), TEST_PORT)
		)
	}

	#[test]
	fn test_addr_from_str_name() {
		let val = format!("{}:{}", TEST_DOMAIN.as_str(), TEST_PORT);
		assert_eq!(
			SocksAddr::from_str(&val).unwrap(),
			SocksAddr::new(TEST_DOMAIN.clone().into(), TEST_PORT)
		)
	}

	#[test]
	fn test_addr_from_str_error() {
		{
			// Address has no port
			let e = SocksAddr::from_str("hello.world").unwrap_err();
			if let ReadError::InvalidAddress(_) = e {
			} else {
				panic!("{:?} is not the correct type", e);
			}
		}
		{
			// Bad domain
			let e = SocksAddr::from_str("bad__.domain:443").unwrap_err();
			assert!(
				matches!(e, ReadError::InvalidDomain(_)),
				"{:?} is not the correct type",
				e
			);
		}
		{
			// Bad domain
			let e = SocksAddr::from_str("bad*.domain:443").unwrap_err();
			assert!(
				matches!(e, ReadError::InvalidDomain(_)),
				"{:?} is not the correct type",
				e
			);
		}
		{
			// Bad port
			let e = SocksAddr::from_str("hello.world:bad_port").unwrap_err();
			assert!(
				matches!(e, ReadError::InvalidPort(_)),
				"{:?} is not the correct type",
				e
			);
		}
		{
			// Missing port
			let e = SocksAddr::from_str("hello.world:").unwrap_err();
			assert!(
				matches!(e, ReadError::InvalidAddress(_)),
				"{:?} is not the correct type",
				e
			);
		}
	}

	#[test]
	fn test_addr_display() {
		let inputs = [
			SocksAddr::new(TEST_IPV4.into(), TEST_PORT),
			SocksAddr::new(TEST_IPV6.into(), TEST_PORT),
			SocksAddr::new(TEST_DOMAIN.clone().into(), TEST_PORT),
		];
		let expected_results = [
			SocketAddr::new(TEST_IPV4.into(), TEST_PORT).to_string(),
			SocketAddr::new(TEST_IPV6.into(), TEST_PORT).to_string(),
			format!("{}:{}", TEST_DOMAIN.as_str(), TEST_PORT),
		];
		for (input, expected) in inputs.iter().zip(expected_results.iter()) {
			assert_eq!(
				&input.to_string(),
				expected,
				"cannot use to_string on {:?} to '{}'",
				input,
				expected
			);
		}
	}
}
