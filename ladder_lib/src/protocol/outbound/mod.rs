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

pub mod socket;
pub mod tunnel;

use super::{common::ProxyStream, ProxyContext};
use crate::prelude::*;
use std::io;

#[async_trait]
pub trait TcpConnector: Send + Sync {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<ProxyStream, Error>;
}

#[async_trait]
pub trait TcpStreamConnector: Send + Sync {
	async fn connect_stream<'a>(
		&'a self,
		stream: ProxyStream,
		dst: &'a SocksAddr,
		context: &'a dyn ProxyContext,
	) -> Result<ProxyStream, Error>;

	fn addr(&self) -> &SocksAddr;
}

pub trait GetConnector {
	fn get_udp_connector(&self) -> Option<UdpConnector<'_>>;
}

#[async_trait]
pub trait ConnectUdpSocket: Send + Sync {
	async fn connect_socket(
		&self,
		context: &dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, Error>;

	async fn connect_socket_stream<'a>(
		&'a self,
		stream: socket::UdpProxyStream,
		context: &'a dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, Error>;
}

#[async_trait]
pub trait ConnectUdpOverTcpSocket: Send + Sync {
	async fn connect(&self, context: &dyn ProxyContext) -> Result<UdpSocketOrTunnelStream, Error>;

	async fn connect_stream<'a>(
		&'a self,
		stream: ProxyStream,
		context: &'a dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, Error>;
}

#[async_trait]
pub trait ConnectUdpTunnel: Send + Sync {
	async fn connect_tunnel(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, Error>;

	async fn connect_tunnel_stream<'a>(
		&'a self,
		dst: &'a SocksAddr,
		stream: tunnel::UdpProxyStream,
		context: &'a dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, Error>;
}

#[async_trait]
pub trait ConnectUdpOverTcpTunnel: Send + Sync {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, Error>;

	async fn connect_stream<'a>(
		&'a self,
		dst: &'a SocksAddr,
		stream: ProxyStream,
		context: &'a dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, Error>;
}

pub enum UdpConnector<'a> {
	Socket(Box<dyn ConnectUdpSocket + 'a>),
	SocketOverTcp(Box<dyn ConnectUdpOverTcpSocket + 'a>),
	Tunnel(Box<dyn ConnectUdpTunnel + 'a>),
	TunnelOverTcp(Box<dyn ConnectUdpOverTcpTunnel + 'a>),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("IO error ({0})")]
	Io(io::Error),
	#[error("domain '{0}' cannot be resolved")]
	NotResolved(SocksDestination),
	#[error("protocol error ({0})")]
	Protocol(BoxStdErr),
	#[error("authentication required but none provided")]
	EmptyAuthentication,
	#[error("failed authentication ({0})")]
	FailedAuthentication(BoxStdErr),
	#[error("not allowed by routing rules")]
	NotAllowed,
	#[error("TCP not supported")]
	TcpNotSupported,
	#[error("UDP not supported")]
	UdpNotSupported,
	#[error("cannot connect over another stream")]
	CannotConnectOverStream,
}

impl Error {
	#[must_use]
	pub fn is_timeout(&self) -> bool {
		if let Self::Io(io) = self {
			io.kind() == io::ErrorKind::TimedOut
		} else {
			false
		}
	}

	#[must_use]
	pub fn new_timeout() -> Self {
		Self::Io(io::ErrorKind::TimedOut.into())
	}

	#[must_use]
	pub fn into_io_err(self) -> io::Error {
		if let Self::Io(e) = self {
			e
		} else {
			io::Error::new(io::ErrorKind::InvalidData, self)
		}
	}
}

impl From<io::Error> for Error {
	#[inline]
	fn from(err: io::Error) -> Self {
		Self::Io(err)
	}
}

pub enum UdpSocketOrTunnelStream {
	Socket(socket::UdpProxyStream),
	Tunnel(tunnel::UdpProxyStream),
}
