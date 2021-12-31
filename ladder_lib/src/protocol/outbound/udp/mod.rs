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
	super::{common::BytesStream, ProxyContext, SocksAddr},
	Error,
};
use async_trait::async_trait;

pub mod socket;
pub mod tunnel;

pub trait GetConnector {
	fn get_udp_connector(&self) -> Option<Connector<'_>>;
}

#[async_trait]
pub trait ConnectSocket: Send + Sync {
	async fn connect_socket(
		&self,
		context: &dyn ProxyContext,
	) -> Result<SocketOrTunnelStream, Error>;

	async fn connect_socket_stream<'a>(
		&'a self,
		stream: socket::DatagramStream,
		context: &'a dyn ProxyContext,
	) -> Result<SocketOrTunnelStream, Error>;
}

#[async_trait]
pub trait ConnectSocketOverTcp: Send + Sync {
	async fn connect(&self, context: &dyn ProxyContext) -> Result<SocketOrTunnelStream, Error>;

	async fn connect_stream<'a>(
		&'a self,
		stream: BytesStream,
		context: &'a dyn ProxyContext,
	) -> Result<SocketOrTunnelStream, Error>;
}

#[async_trait]
pub trait ConnectTunnel: Send + Sync {
	async fn connect_tunnel(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<SocketOrTunnelStream, Error>;

	async fn connect_tunnel_stream<'a>(
		&'a self,
		dst: &'a SocksAddr,
		stream: tunnel::DatagramStream,
		context: &'a dyn ProxyContext,
	) -> Result<SocketOrTunnelStream, Error>;
}

#[async_trait]
pub trait ConnectTunnelOverTcp: Send + Sync {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<SocketOrTunnelStream, Error>;

	async fn connect_stream<'a>(
		&'a self,
		dst: &'a SocksAddr,
		stream: BytesStream,
		context: &'a dyn ProxyContext,
	) -> Result<SocketOrTunnelStream, Error>;
}

pub enum Connector<'a> {
	Socket(Box<dyn ConnectSocket + 'a>),
	SocketOverTcp(Box<dyn ConnectSocketOverTcp + 'a>),
	Tunnel(Box<dyn ConnectTunnel + 'a>),
	TunnelOverTcp(Box<dyn ConnectTunnelOverTcp + 'a>),
}

pub enum SocketOrTunnelStream {
	Socket(socket::DatagramStream),
	Tunnel(tunnel::DatagramStream),
}
