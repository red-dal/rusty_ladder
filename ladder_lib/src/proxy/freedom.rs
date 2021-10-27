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
	protocol::{
		outbound::socket::{UdpProxyStream, UdpSocketWrapper},
		ConnectUdpSocket, GetConnector, GetProtocolName, OutboundError, ProxyContext, ProxyStream,
		TcpConnector, UdpConnector as ProtoConnector, UdpSocketOrTunnelStream,
	},
};
use async_trait::async_trait;
use std::net::SocketAddr;

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Settings {}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		"freedom"
	}
}

#[async_trait]
impl TcpConnector for Settings {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<ProxyStream, OutboundError> {
		let stream = context.dial_tcp(dst).await?;
		Ok(stream.into())
	}
}

impl GetConnector for Settings {
	fn get_udp_connector(&self) -> Option<ProtoConnector<'_>> {
		Some(ProtoConnector::Socket(Box::new(UdpConnector {})))
	}
}

struct UdpConnector {}

#[async_trait]
impl ConnectUdpSocket for UdpConnector {
	async fn connect_socket(
		&self,
		_context: &dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, OutboundError> {
		let read_half = UdpSocketWrapper::bind(SocketAddr::new([0, 0, 0, 0].into(), 0)).await?;
		let write_half = read_half.clone();
		Ok(UdpSocketOrTunnelStream::Socket(UdpProxyStream {
			read_half: Box::new(read_half),
			write_half: Box::new(write_half),
		}))
	}

	async fn connect_socket_stream<'a>(
		&'a self,
		_stream: UdpProxyStream,
		_context: &'a dyn ProxyContext,
	) -> Result<UdpSocketOrTunnelStream, OutboundError> {
		Err(OutboundError::CannotConnectOverStream)
	}
}
