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

use crate::{
	prelude::*,
	protocol::{inbound::HandshakeError, outbound::Error as OutboundError, socks_addr::ReadError},
};
use num_enum::TryFromPrimitive;
use std::{fmt::Display, io};

pub const VER5: u8 = 5;
/// Subnegotiation version.
///
/// See more at <https://datatracker.ietf.org/doc/html/rfc1929#section-2>
pub const SUB_VERS: u8 = 1_u8;
pub(super) const AUTH_SUCCESSFUL: u8 = 0;
pub(super) const AUTH_FAILED: u8 = 0xff;
pub(super) const VAL_NO_AUTH: u8 = 0_u8;
pub(super) const VAL_NO_USER_PASS: u8 = 2_u8;

#[derive(Debug, TryFromPrimitive, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum CommandCode {
	Connect = 1,
	Bind = 2,
	Udp = 3,
}

impl Display for CommandCode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			CommandCode::Connect => write!(f, "CONNECT"),
			CommandCode::Bind => write!(f, "BIND"),
			CommandCode::Udp => write!(f, "UDP_ASSOCIATE"),
		}?;
		write!(f, "({})", *self as u8)
	}
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AcceptableMethod {
	NoAuthentication = VAL_NO_AUTH,
	UsernamePassword = VAL_NO_USER_PASS,
}

#[derive(Debug, TryFromPrimitive, PartialEq, Copy, Clone)]
#[repr(u8)]
/// SOCKS5 reply code.
///
/// See more at <https://datatracker.ietf.org/doc/html/rfc1928#section-6>.
pub enum ReplyCode {
	Succeeded = 0,
	SocksFailure = 1,
	NotAllowedByRuleset = 2,
	HostUnreachable = 4,
	ConnectionsRefused = 5,
	TtlExpired = 6,
	CommandNotSupported = 7,
	AddressTypeNotSupported = 8,
}

impl ReplyCode {
	#[must_use]
	pub const fn as_str(self) -> &'static str {
		match self {
			ReplyCode::Succeeded => "succeeded",
			ReplyCode::SocksFailure => "socks failure",
			ReplyCode::NotAllowedByRuleset => "not allowed by ruleset",
			ReplyCode::HostUnreachable => "host unreachable",
			ReplyCode::ConnectionsRefused => "connection refused",
			ReplyCode::TtlExpired => "ttl expired",
			ReplyCode::CommandNotSupported => "command not supported",
			ReplyCode::AddressTypeNotSupported => "address type not supported",
		}
	}

	#[inline]
	#[must_use]
	pub const fn val(self) -> u8{
		self as u8
	}
}

impl Display for ReplyCode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.as_str())
	}
}

pub struct Authentication<'a> {
	pub user: Cow<'a, [u8]>,
	pub pass: Cow<'a, [u8]>,
}

impl Authentication<'_> {}

pub struct Request {
	pub code: u8,
	pub addr: SocksAddr,
}

pub type Reply = Request;

impl Request {
	/// Read the request/reply in the following format:
	///```not_rust
	/// +----+-----+-------+------+-------------------+----------+
	/// |VER | CMD |  RSV  | ATYP | DST.ADDR/BND.ADDR | DST.PORT |
	/// +----+-----+-------+------+-------------------+----------+
	/// | 1  |  1  | X'00' |  1   |     Variable      |    2     |
	/// +----+-----+-------+------+-------------------+----------+
	///```
	pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, SocksOrIoError> {
		let mut tmp_buf = [0_u8; 3];
		reader.read_exact(&mut tmp_buf).await?;

		let (ver, cmd_rep, _) = (tmp_buf[0], tmp_buf[1], tmp_buf[2]);
		check_version(ver)?;

		let addr = match SocksAddr::async_read_from(reader).await {
			Ok(addr) => addr,
			Err(e) => {
				return Err(match e {
					ReadError::Io(e) => SocksOrIoError::Io(e),
					_ => SocksOrIoError::Socks(Error::CannotReadAddr(e)),
				})
			}
		};
		Ok(Self {
			code: cmd_rep,
			addr,
		})
	}

	/// Write the request/reply in the following format:
	///```not_rust
	/// +----+-----+-------+------+-------------------+----------+
	/// |VER | CMD |  RSV  | ATYP | DST.ADDR/BND.ADDR | DST.PORT |
	/// +----+-----+-------+------+-------------------+----------+
	/// | 1  |  1  | X'00' |  1   |     Variable      |    2     |
	/// +----+-----+-------+------+-------------------+----------+
	///```
	pub fn write_into(&self, buf: &mut Vec<u8>) {
		buf.clear();
		buf.put_u8(VER5);
		buf.put_u8(self.code);
		buf.put_u8(0);
		self.addr.write_to(buf);
	}
}

pub enum SocksOrIoError {
	Io(io::Error),
	Socks(Error),
}

impl From<io::Error> for SocksOrIoError {
	#[inline]
	fn from(e: io::Error) -> Self {
		SocksOrIoError::Io(e)
	}
}

impl From<Error> for SocksOrIoError {
	#[inline]
	fn from(e: Error) -> Self {
		SocksOrIoError::Socks(e)
	}
}

impl From<SocksOrIoError> for OutboundError {
	#[inline]
	fn from(e: SocksOrIoError) -> Self {
		match e {
			SocksOrIoError::Io(e) => OutboundError::Io(e),
			SocksOrIoError::Socks(e) => OutboundError::Protocol(e.into()),
		}
	}
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("wrong socks version '{0}'")]
	WrongVersion(u8),
	#[error("unsupported address type '{0:?}'")]
	UnsupportedMethod(Vec<u8>),
	#[error("unsupported authentication method '{0}'")]
	UnsupportedAddressType(u8),
	#[error("unknown command code '{0}'")]
	UnknownCommand(u8),
	#[error("unsupported command {0}")]
	UnsupportedCommand(CommandCode),
	#[error("reply error code '{0}'")]
	FailedReply(ReplyCode),
	#[error("unknown reply code '{0}'")]
	UnknownReplyCode(u8),
	#[error("failed authentication")]
	FailedAuthentication,
	#[error("cannot read address ({0})")]
	CannotReadAddr(ReadError),
	#[error("{0}")]
	Custom(BoxStdErr),
}

impl From<Error> for OutboundError {
	#[inline]
	fn from(e: Error) -> Self {
		OutboundError::Protocol(e.into())
	}
}

impl From<Error> for HandshakeError {
	#[inline]
	fn from(e: Error) -> Self {
		HandshakeError::Protocol(e.into())
	}
}

#[inline]
pub fn check_version(ver: u8) -> Result<(), Error> {
	if ver != VER5 {
		return Err(Error::WrongVersion(ver));
	}
	Ok(())
}
