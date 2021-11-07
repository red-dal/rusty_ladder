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

use super::common::{AsyncReadWrite, GetProtocolName, BytesStream};
use crate::{prelude::*, protocol::outbound};
use async_trait::async_trait;
use std::{
	fmt::{self, Formatter},
	io,
};

#[cfg(feature = "use-udp")]
pub mod udp;

#[async_trait]
pub trait TcpAcceptor: GetProtocolName {
	async fn accept_tcp<'a>(&'a self, stream: BytesStream)
		-> Result<AcceptResult<'a>, AcceptError>;
}

pub enum AcceptResult<'a> {
	Tcp(Box<dyn FinishHandshake + 'a>, SocksAddr),
	#[cfg(feature = "use-udp")]
	Udp(udp::PacketStream),
}

#[async_trait]
pub trait FinishHandshake: Send {
	async fn finish(self: Box<Self>) -> Result<BytesStream, HandshakeError>;
	async fn finish_err(self: Box<Self>, err: &outbound::Error) -> Result<(), HandshakeError>;
}

pub struct PlainHandshakeHandler(pub BytesStream);

#[async_trait]
impl FinishHandshake for PlainHandshakeHandler {
	async fn finish(self: Box<Self>) -> Result<BytesStream, HandshakeError> {
		return Ok(self.0);
	}

	async fn finish_err(self: Box<Self>, _err: &outbound::Error) -> Result<(), HandshakeError> {
		return Ok(());
	}
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
	#[error("inbound IO error ({0})")]
	Io(io::Error),
	#[error("inbound protocol error ({0})")]
	Protocol(BoxStdErr),
	#[error("TCP stream not acceptable by inbound")]
	TcpNotAcceptable,
	#[error("UDP stream not acceptable by inbound")]
	UdpNotAcceptable,
}

impl HandshakeError {}

impl From<io::Error> for HandshakeError {
	#[inline]
	fn from(e: io::Error) -> Self {
		Self::Io(e)
	}
}

pub enum AcceptError {
	Io(io::Error),
	Protocol((Box<dyn AsyncReadWrite>, BoxStdErr)),
	TcpNotAcceptable,
	UdpNotAcceptable,
}

impl AcceptError {
	#[inline]
	pub fn new_protocol(stream: Box<dyn AsyncReadWrite>, e: impl Into<BoxStdErr>) -> Self {
		AcceptError::Protocol((stream, e.into()))
	}

	#[inline]
	#[allow(clippy::missing_errors_doc)]
	pub fn new_protocol_err<T>(
		stream: Box<dyn AsyncReadWrite>,
		e: impl Into<BoxStdErr>,
	) -> Result<T, Self> {
		Err(AcceptError::Protocol((stream, e.into())))
	}
}

impl fmt::Display for AcceptError {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			AcceptError::Io(e) => write!(f, "inbound handshake IO error ({})", e),
			AcceptError::Protocol((_, e)) => write!(f, "inbound handshake protocol error ({})", e),
			AcceptError::TcpNotAcceptable => write!(f, "inbound cannot accept TCP"),
			AcceptError::UdpNotAcceptable => write!(f, "inbound cannot accept UDP"),
		}
	}
}

impl From<io::Error> for AcceptError {
	fn from(e: io::Error) -> Self {
		Self::Io(e)
	}
}
