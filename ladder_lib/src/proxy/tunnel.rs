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
		inbound::{AcceptError, AcceptResult},
		GetProtocolName, Network, PlainHandshakeHandler, ProxyStream, TcpAcceptor,
	},
};

const PROTOCOL_NAME: &str = "tunnel";

fn default_network_tcp() -> Network {
	Network::Tcp
}

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Settings {
	dst: SocksAddr,
	#[cfg_attr(feature = "use_serde", serde(default = "default_network_tcp"))]
	network: Network,
}

impl Settings {}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}

	fn network(&self) -> Network {
		self.network
	}
}

#[async_trait]
impl TcpAcceptor for Settings {
	#[inline]
	async fn accept_tcp<'a>(
		&'a self,
		stream: ProxyStream,
	) -> Result<AcceptResult<'a>, AcceptError> {
		if self.network.use_tcp() {
			Ok(AcceptResult::new_tcp(
				Box::new(PlainHandshakeHandler(stream)),
				self.dst.clone(),
			))
		} else {
			Err(AcceptError::TcpNotAcceptable)
		}
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::Settings;
	use crate::{
		prelude::*,
		protocol::{
			inbound::{Session, UdpProxyStream, UdpRecv, UdpResult, UdpSend},
			UdpAcceptor,
		},
	};
	use std::io;
	use tokio::net::UdpSocket;

	#[async_trait]
	impl UdpAcceptor for Settings {
		async fn accept_udp(&self, sock: UdpSocket) -> Result<UdpProxyStream, BoxStdErr> {
			if self.network.use_udp() {
				let sock = Arc::new(sock);

				let stream = UdpProxyStream {
					read_half: Box::new(ReadHalfWrapper(sock.clone(), self.dst.clone())),
					write_half: Box::new(sock),
				};

				Ok(stream)
			} else {
				Err("UDP not acceptable by inbound".into())
			}
		}
	}

	#[derive(Clone)]
	pub struct ReadHalfWrapper(pub Arc<UdpSocket>, pub SocksAddr);

	#[async_trait]
	impl UdpRecv for ReadHalfWrapper {
		async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<UdpResult> {
			let (len, src) = self.0.recv_from(buf).await?;
			Ok(UdpResult {
				src: Some(src),
				len,
				dst: self.1.clone(),
			})
		}
	}

	#[async_trait]
	impl UdpSend for Arc<UdpSocket> {
		async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize> {
			trace!(
				"Sending UDP packet for session ({} -> {})",
				sess.src,
				sess.dst
			);
			self.send_to(buf, sess.src).await
		}
	}
}
