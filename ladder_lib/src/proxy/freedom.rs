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
		outbound::{Error as OutboundError, TcpConnector},
		BufBytesStream, GetProtocolName, ProxyContext,
	},
};
use async_trait::async_trait;

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
	) -> Result<BufBytesStream, OutboundError> {
		let stream = context.dial_tcp(dst).await?;
		Ok(stream.into())
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::Settings;
	use crate::protocol::{
		outbound::{
			udp::{socket, ConnectSocket, Connector, GetConnector, SocketOrTunnelStream},
			Error as OutboundError,
		},
		ProxyContext,
	};
	use async_trait::async_trait;
	use std::net::SocketAddr;

	impl GetConnector for Settings {
		fn get_udp_connector(&self) -> Option<Connector<'_>> {
			Some(Connector::Socket(Box::new(InnerConnector {})))
		}
	}

	struct InnerConnector {}

	#[async_trait]
	impl ConnectSocket for InnerConnector {
		async fn connect_socket(
			&self,
			_context: &dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let read_half =
				socket::UdpSocketWrapper::bind(SocketAddr::new([0, 0, 0, 0].into(), 0)).await?;
			let write_half = read_half.clone();
			Ok(SocketOrTunnelStream::Socket(socket::DatagramStream {
				read_half: Box::new(read_half),
				write_half: Box::new(write_half),
			}))
		}

		async fn connect_socket_stream<'a>(
			&'a self,
			_stream: socket::DatagramStream,
			_context: &'a dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			Err(OutboundError::CannotConnectOverStream)
		}
	}
}
