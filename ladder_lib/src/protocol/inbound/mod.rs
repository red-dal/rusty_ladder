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

use super::{
	common::{AsyncReadWrite, GetProtocolName},
	BufBytesStream,
};
use crate::{network, prelude::*, protocol::outbound};
use async_trait::async_trait;
use std::{
	fmt::{self, Formatter},
	io,
};

#[cfg(feature = "use-udp")]
pub mod udp;

#[derive(Debug)]
pub struct SessionInfo {
	pub addr: network::Addrs,
	pub is_transport_empty: bool,
}

#[async_trait]
pub trait StreamAcceptor: GetProtocolName {
	/// Accepting proxy on `stream`.
	///
	/// # Examples
	/// ```
	/// use ladder_lib::protocol::{
	///		inbound::{ StreamAcceptor, AcceptError, Handshake, SessionInfo },
	///		CompositeBytesStream, AsyncReadWrite, GetProtocolName
	///	};
	/// use async_trait::async_trait;
	/// use std::io::Cursor;
	///
	/// struct Example;
	///
	/// impl GetProtocolName for Example {
	///		fn protocol_name(&self) -> &'static str {
	///			"example"
	///		}
	/// }
	///
	/// // Implementing trait.
	/// #[async_trait]
	/// impl StreamAcceptor for Example {
	///		async fn accept_stream<'a>(
	///			&'a self,
	///			stream: Box<dyn AsyncReadWrite>,
	///			info: SessionInfo,
	///		) -> Result<Handshake<'a>, AcceptError> {
	///			// Try to determine destination from client request.
	///			unimplemented!()
	///		}
	/// }
	///
	/// // Using trait.
	/// async move {
	///		let info = unimplemented!();
	///		let stream = unimplemented!();
	///		let handshake = Example.accept_stream(stream, info).await;
	///		if let Ok(Handshake::Stream(handshake, dst)) = handshake {
	///			// `dst` is the destination requested by client.
	///			// Now do something here...
	///			// Then finish handshake with `finish` or `finish_err`.
	///			let stream = handshake.finish().await.unwrap();
	///		}
	/// };
	/// ```
	async fn accept_stream<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		info: SessionInfo,
	) -> Result<Handshake<'a>, AcceptError>;
}

pub enum Handshake<'a> {
	/// (proxy handshake, destination address requested by client)
	Stream(Box<dyn Finish + 'a>, SocksAddr),
	#[cfg(feature = "use-udp")]
	Datagram(udp::DatagramStream),
}

#[async_trait]
pub trait Finish: Send {
	async fn finish(self: Box<Self>) -> Result<BufBytesStream, HandshakeError>;
	async fn finish_err(self: Box<Self>, err: &outbound::Error) -> Result<(), HandshakeError>;
}

pub struct SimpleHandshake(pub BufBytesStream);

#[async_trait]
impl Finish for SimpleHandshake {
	async fn finish(self: Box<Self>) -> Result<BufBytesStream, HandshakeError> {
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
	Protocol(BoxStdErr),
	ProtocolSilentDrop(Box<dyn AsyncReadWrite>, BoxStdErr),
	ProtocolRedirect(Box<dyn AsyncReadWrite>, SocketAddr, BoxStdErr),
	TcpNotAcceptable,
	UdpNotAcceptable,
}

impl AcceptError {
	#[inline]
	pub fn new_silent_drop(stream: Box<dyn AsyncReadWrite>, e: impl Into<BoxStdErr>) -> Self {
		AcceptError::ProtocolSilentDrop(stream, e.into())
	}

	#[inline]
	#[allow(clippy::missing_errors_doc)]
	pub fn new_protocol_err<T>(
		stream: Box<dyn AsyncReadWrite>,
		e: impl Into<BoxStdErr>,
	) -> Result<T, Self> {
		Err(AcceptError::ProtocolSilentDrop(stream, e.into()))
	}
}

impl fmt::Display for AcceptError {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			AcceptError::Io(e) => write!(f, "inbound handshake IO error ({})", e),
			AcceptError::ProtocolSilentDrop(_, e) => {
				write!(f, "inbound handshake protocol error ({})", e)
			}
			AcceptError::ProtocolRedirect(_, _, e) => {
				write!(f, "inbound handshake protocol error ({})", e)
			}
			AcceptError::TcpNotAcceptable => write!(f, "inbound cannot accept TCP"),
			AcceptError::UdpNotAcceptable => write!(f, "inbound cannot accept UDP"),
			AcceptError::Protocol(e) => write!(f, "proxy protocol error ({})", e),
		}
	}
}

impl From<io::Error> for AcceptError {
	fn from(e: io::Error) -> Self {
		Self::Io(e)
	}
}
