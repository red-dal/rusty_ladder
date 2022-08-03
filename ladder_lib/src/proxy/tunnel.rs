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
		inbound::{AcceptError, Handshake, SimpleHandshake, SessionInfo, StreamAcceptor},
		AsyncReadWrite, BufBytesStream, GetProtocolName, Network,
	},
};

pub const PROTOCOL_NAME: &str = "tunnel";

#[cfg(feature = "use_serde")]
fn default_network_tcp() -> Network {
	Network::default()
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Settings {
	dst: SocksAddr,
	#[cfg_attr(feature = "use_serde", serde(default = "default_network_tcp"))]
	network: Network,
}

impl Settings {
	/// This is a helper method and will always return `Ok(Self)`.
	///
	/// # Errors
	///
	/// This method will never return any error.
	#[inline]
	pub fn build<E>(self) -> Result<Self, E> {
		Ok(self)
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// tunnel://bind_addr:bind_port/dst
	/// ```
	/// where `dst` is percent-encoded string
	/// that can be parsed into [`SocksAddr`].
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		let dst_str = percent_encoding::percent_decode_str(url.path()).decode_utf8()?;
		// Skip the first character '/'
		let dst = SocksAddr::from_str(&dst_str[1..])?;
		Ok(Self {
			dst,
			network: Network::Tcp,
		})
	}
}

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
impl StreamAcceptor for Settings {
	#[inline]
	async fn accept_stream<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		_info: SessionInfo,
	) -> Result<Handshake<'a>, AcceptError> {
		if self.network.use_tcp() {
			Ok(Handshake::Stream(
				Box::new(SimpleHandshake(BufBytesStream::from(stream))),
				self.dst.clone(),
			))
		} else {
			Err(AcceptError::TcpNotAcceptable)
		}
	}
}

fn get_network_name(net: Network) -> &'static str {
	match net {
		Network::Tcp => "tcp",
		Network::Udp => "udp",
		Network::TcpAndUdp => "tcp-udp",
	}
}

impl crate::protocol::DisplayInfo for Settings {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let net = get_network_name(self.network);
		write!(f, "tunnel-{net}")
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let net = get_network_name(self.network);
		let dst = &self.dst;
		write!(f, "tunnel({net},add:'{dst}')")
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::Settings;
	use crate::{
		prelude::*,
		protocol::inbound::udp::{
			Acceptor, DatagramInfo, DatagramStream, RecvDatagram, SendDatagram, Session,
		},
	};
	use std::io;
	use tokio::net::UdpSocket;

	#[async_trait]
	impl Acceptor for Settings {
		async fn accept_udp(&self, sock: UdpSocket) -> Result<DatagramStream, BoxStdErr> {
			if self.network.use_udp() {
				let sock = Arc::new(sock);

				let stream = DatagramStream {
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
	impl RecvDatagram for ReadHalfWrapper {
		async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<DatagramInfo> {
			let (len, src) = self.0.recv_from(buf).await?;
			Ok(DatagramInfo {
				src: Some(src),
				len,
				dst: self.1.clone(),
			})
		}
	}

	#[async_trait]
	impl SendDatagram for Arc<UdpSocket> {
		async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize> {
			trace!(
				"Sending UDP datagram for session ({} -> {})",
				sess.src,
				sess.dst
			);
			self.send_to(buf, sess.src).await
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use std::str::FromStr;
		use url::Url;

		let data = [
			(
				"tunnel://127.0.0.1:22222/192.168.168.168%3A16816",
				Settings {
					dst: "192.168.168.168:16816".parse().unwrap(),
					network: Network::Tcp,
				},
			),
			(
				"tunnel://127.0.0.1:22222/%5B%3A%3A1%5D%3A11111",
				Settings {
					dst: "[::1]:11111".parse().unwrap(),
					network: Network::Tcp,
				},
			),
		];

		for (url, expected) in data {
			let url = Url::from_str(url).unwrap();
			let output = Settings::parse_url(&url).unwrap();
			assert_eq!(expected, output);
		}
	}

	#[test]
	fn test_display_info() {
		use crate::protocol::DisplayInfo;

		let mut s = Settings {
			dst: "not.localhost:12345".parse().unwrap(),
			network: Network::Tcp,
		};
		assert_eq!(s.brief().to_string(), "tunnel-tcp");
		assert_eq!(
			s.detail().to_string(),
			"tunnel(tcp,add:'not.localhost:12345')"
		);

		s.network = Network::Udp;
		assert_eq!(s.brief().to_string(), "tunnel-udp");
		assert_eq!(
			s.detail().to_string(),
			"tunnel(udp,add:'not.localhost:12345')"
		);

		s.network = Network::TcpAndUdp;
		assert_eq!(s.brief().to_string(), "tunnel-tcp-udp");
		assert_eq!(
			s.detail().to_string(),
			"tunnel(tcp-udp,add:'not.localhost:12345')"
		);
	}
}
