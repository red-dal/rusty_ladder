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

use super::common::{AsyncReadWrite, GetProtocolName, ProxyStream};
use crate::{prelude::*, protocol::outbound};
use async_trait::async_trait;
use std::{
	fmt::{self, Formatter},
	io,
};
use tokio::net::UdpSocket;

#[async_trait]
pub trait TcpAcceptor: GetProtocolName {
	async fn accept_tcp<'a>(&'a self, stream: ProxyStream)
		-> Result<AcceptResult<'a>, AcceptError>;
}

#[async_trait]
pub trait UdpAcceptor: GetProtocolName {
	async fn accept_udp(&self, sock: UdpSocket) -> Result<UdpProxyStream, BoxStdErr>;
}

pub enum AcceptResult<'a> {
	Tcp((Box<dyn FinishHandshake + 'a>, SocksAddr)),
	#[cfg(feature = "use-udp")]
	Udp(UdpProxyStream),
}

impl<'a> AcceptResult<'a> {
	#[inline]
	#[must_use]
	pub fn new_tcp(handle: Box<dyn FinishHandshake + 'a>, addr: SocksAddr) -> Self {
		AcceptResult::Tcp((handle, addr))
	}

	#[inline]
	#[must_use]
	#[cfg(feature = "use-udp")]
	pub fn new_udp(udp_stream: UdpProxyStream) -> Self {
		AcceptResult::Udp(udp_stream)
	}
}

#[async_trait]
pub trait FinishHandshake: Send {
	async fn finish(self: Box<Self>) -> Result<ProxyStream, HandshakeError>;
	async fn finish_err(self: Box<Self>, err: &outbound::Error) -> Result<(), HandshakeError>;
}

pub struct PlainHandshakeHandler(pub ProxyStream);

#[async_trait]
impl FinishHandshake for PlainHandshakeHandler {
	async fn finish(self: Box<Self>) -> Result<ProxyStream, HandshakeError> {
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

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Session {
	/// Address for local client (source)
	pub src: SocketAddr,
	/// Address for remote server (destination)
	pub dst: SocksAddr,
}

pub struct UdpResult {
	pub len: usize,
	pub src: Option<SocketAddr>,
	pub dst: SocksAddr,
}

#[async_trait]
pub trait UdpRecv: Unpin + Send + Sync {
	async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<UdpResult>;
}

#[async_trait]
pub trait UdpSend: Unpin + Send + Sync {
	async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize>;
}

// pub trait InboundReadWrite: InboundRead + InboundWrite {
// 	fn split_stream(self: Box<Self>) -> (Box<dyn InboundRead>, Box<dyn InboundWrite>);
// }

#[async_trait]
impl<T: UdpRecv + ?Sized> UdpRecv for Box<T> {
	async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<UdpResult> {
		self.as_mut().recv_inbound(buf).await
	}
}

#[async_trait]
impl<T: UdpSend + ?Sized> UdpSend for Box<T> {
	async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize> {
		self.as_mut().send_inbound(sess, buf).await
	}
}

pub struct UdpProxyStream {
	pub read_half: Box<dyn UdpRecv>,
	pub write_half: Box<dyn UdpSend>,
}

#[async_trait]
impl UdpRecv for UdpProxyStream {
	async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<UdpResult> {
		self.read_half.recv_inbound(buf).await
	}
}

#[async_trait]
impl UdpSend for UdpProxyStream {
	async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize> {
		self.write_half.send_inbound(sess, buf).await
	}
}
