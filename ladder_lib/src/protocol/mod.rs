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

pub mod inbound;
pub mod outbound;
pub mod socks_addr;

mod common;
mod proxy_context;

pub use common::{AsyncReadWrite, BoxRead, BoxWrite, GetProtocolName, Network, ProxyStream};
pub use proxy_context::{GetConnectorError, ProxyContext};
// TCP
pub use inbound::{FinishHandshake, PlainHandshakeHandler, TcpAcceptor};
pub use outbound::{Error as OutboundError, TcpConnector, TcpStreamConnector};
// UDP
pub use inbound::UdpAcceptor;
pub use outbound::{
	ConnectUdpOverTcpSocket, ConnectUdpOverTcpTunnel, ConnectUdpSocket, ConnectUdpTunnel,
	GetConnector, UdpConnector, UdpSocketOrTunnelStream,
};
pub use socks_addr::{SocksAddr, SocksDestination};
