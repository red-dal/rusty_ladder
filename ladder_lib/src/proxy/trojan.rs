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

/*!
Implementation of the trojan protocol,
see more at <https://trojan-gfw.github.io/trojan/protocol.html>

But this implementation does not include a security layer such as TLS.
DO NOT use this without a security layer over an unsecure network.

Trojan request format:
```not_rust
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+
```

where target address is a SOCKS5 address:
```not_rust
+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+
```

See more about SOCKS5 address at <https://tools.ietf.org/html/rfc1928#section-5>
*/

use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpStreamConnector},
		AsyncReadWrite, BufBytesStream, GetProtocolName, ProxyContext,
	},
	utils::LazyWriteHalf,
};
use async_trait::async_trait;
use sha2::{Digest, Sha224};

pub const PROTOCOL_NAME: &str = "trojan";

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	pub password: String,
	pub addr: SocksAddr,
}

impl SettingsBuilder {
	/// Creates a Trojan outbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(Settings {
			password: self.password,
			addr: self.addr,
		})
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// trojan://pass@host[:port]
	/// ```
	/// where `pass` is the password used in trojan,
	/// `host` and `port` is the domain/IP and port for proxy server.
	///
	/// If port is not specified, 443 will be used instead.
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(#[allow(unused_variables)] url: &url::Url) -> Result<Self, BoxStdErr> {
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		{
			const DEFAULT_PORT: u16 = 443;
			crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
			crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;

			let password = url.username();
			if password.is_empty() {
				return Err("Trojan password cannot be empty".into());
			}
			let addr = crate::utils::url::get_socks_addr(url, Some(DEFAULT_PORT))?;
			Ok(SettingsBuilder {
				password: password.to_owned(),
				addr,
			})
		}
		#[cfg(not(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls")))]
		{
			Err("TLS transport must be enabled for Trojan".into())
		}
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("trojan-out")
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "trojan-out({addr})", addr = &self.addr)
	}
}

pub struct Settings {
	password: String,
	addr: SocksAddr,
}

impl Settings {
	#[must_use]
	#[inline]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn TcpStreamConnector> {
		Some(self)
	}

	async fn priv_connect<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
	) -> Result<BufBytesStream, OutboundError> {
		debug!(
			"Creating Trojan connection to '{}', target: '{}'",
			&self.addr, dst
		);

		trace!("Sending Trojan request to '{}'", self.addr);

		// perform trojan handshake
		let mut req_buf = Vec::with_capacity(1024);

		password_to_hex(self.password.as_bytes(), &mut req_buf);
		req_buf.put_slice(CRLF);
		req_buf.put_u8(Command::Connect as u8);
		dst.write_to(&mut req_buf);
		req_buf.put_slice(CRLF);

		trace!("Trojan request header length: {} bytes", req_buf.len());

		let (rh, wh) = stream.split();
		let wh = LazyWriteHalf::new(wh, req_buf);
		Ok(BufBytesStream::from_raw(rh, Box::new(wh)))
	}
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpStreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
		_context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		Ok(self.priv_connect(stream, dst).await?)
	}

	#[inline]
	fn addr(&self, _context: &dyn ProxyContext) -> Result<Option<SocksAddr>, OutboundError> {
		Ok(Some(self.addr.clone()))
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::{password_to_hex, Command, Settings};
	use crate::{
		prelude::*,
		protocol::{
			self,
			outbound::{
				udp::{
					socket::{DatagramStream, RecvDatagram, SendDatagram},
					ConnectSocketOverTcp, GetConnector, SocketOrTunnelStream,
				},
				Error as OutboundError,
			},
			socks_addr::ReadError,
			AsyncReadWrite, BoxRead, ProxyContext,
		},
		utils::LazyWriteHalf,
	};
	use async_trait::async_trait;
	use std::io;

	impl GetConnector for Settings {
		fn get_udp_connector(&self) -> Option<protocol::outbound::udp::Connector<'_>> {
			return Some(protocol::outbound::udp::Connector::SocketOverTcp(Box::new(
				UdpConnector { settings: self },
			)));
		}
	}

	struct UdpReadHalf {
		inner: BoxRead,
	}

	impl UdpReadHalf {
		fn new(inner: BoxRead) -> Self {
			Self { inner }
		}
	}

	#[async_trait]
	impl RecvDatagram for UdpReadHalf {
		async fn recv_src(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocksAddr)> {
			// Each UDP datagram has the following format:
			//
			// +------+----------+----------+--------+---------+----------+
			// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
			// +------+----------+----------+--------+---------+----------+
			// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
			// +------+----------+----------+--------+---------+----------+
			//
			// See more at <https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md>

			debug_assert!(buf.len() > 4 * 1024);
			// Reading address (ATYP, DST.ADDR, DST.PORT)
			let src = SocksAddr::async_read_from(&mut self.inner)
				.await
				.map_err(|e| {
					if let ReadError::Io(e) = e {
						e
					} else {
						io::Error::new(io::ErrorKind::InvalidData, e)
					}
				})?;
			// Reading length and CRLF
			let (len, crlf) = {
				let mut tmp = [0_u8; 4];
				let len = [tmp[0], tmp[1]];
				let crlf = [tmp[2], tmp[3]];
				self.inner.read_exact(&mut tmp).await?;
				(usize::from(u16::from_be_bytes(len)), crlf)
			};
			if crlf != CRLF {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!("expected CRLF '{:?}', but get '{:?}'", CRLF, crlf),
				));
			}
			if len > buf.len() {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"Udp recv buffer size too small ({} bytes), {} bytes needed",
						buf.len(),
						len
					),
				));
			}
			// Reading payload
			self.inner.read_exact(&mut buf[..len]).await?;
			return Ok((len, src));
		}
	}

	struct UdpWriteHalf<W: AsyncWrite + Unpin + Send + Sync> {
		inner: W,
		req_buf: Vec<u8>,
	}

	impl<W: AsyncWrite + Unpin + Send + Sync> UdpWriteHalf<W> {
		fn new(inner: W) -> Self {
			Self {
				inner,
				req_buf: Vec::with_capacity(4 * 1024),
			}
		}
	}

	#[async_trait]
	impl<W: AsyncWrite + Unpin + Send + Sync> SendDatagram for UdpWriteHalf<W> {
		async fn send_dst(&mut self, dst: &SocksAddr, payload: &[u8]) -> std::io::Result<usize> {
			let payload_len = u16::try_from(payload.len()).unwrap_or_else(|_| {
				warn!(
					"UDP payload too large for trojan protocol: {}",
					payload.len()
				);
				u16::MAX
			});

			let payload = &payload[..payload_len as usize];

			let buf = &mut self.req_buf;

			dst.write_to(buf);
			buf.put_u16(payload_len);
			buf.put_slice(CRLF);
			buf.put_slice(payload);

			self.inner.write_all(buf).await?;

			buf.clear();
			return Ok(payload.len());
		}

		async fn shutdown(&mut self) -> std::io::Result<()> {
			return self.inner.shutdown().await;
		}
	}

	struct UdpConnector<'a> {
		settings: &'a Settings,
	}

	#[async_trait]
	impl ConnectSocketOverTcp for UdpConnector<'_> {
		async fn connect(
			&self,
			context: &dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let stream = context.dial_tcp(&self.settings.addr).await?;
			self.connect_stream(Box::new(stream), context).await
		}

		async fn connect_stream<'a>(
			&'a self,
			stream: Box<dyn AsyncReadWrite>,
			_context: &'a dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let mut req_buf = Vec::with_capacity(512);
			password_to_hex(self.settings.password.as_bytes(), &mut req_buf);
			req_buf.put_slice(CRLF);
			req_buf.put_u8(Command::UdpAssociate as u8);
			// dummy address
			self.settings.addr.write_to(&mut req_buf);
			req_buf.put_slice(CRLF);

			let (rh, wh) = stream.split();
			let write_half = LazyWriteHalf::new(wh, req_buf);

			let read_half = UdpReadHalf::new(rh);
			let write_half = UdpWriteHalf::new(write_half);

			return Ok(SocketOrTunnelStream::Socket(DatagramStream {
				read_half: Box::new(read_half),
				write_half: Box::new(write_half),
			}));
		}
	}
}

#[repr(u8)]
enum Command {
	Connect = 0x1,
	#[cfg(feature = "use-udp")]
	UdpAssociate = 0x3,
}

fn password_to_hex(password: &[u8], buf: &mut impl BufMut) {
	let mut hasher = Sha224::new();
	hasher.update(password);

	let hash = hasher.finalize();
	let hex = format!("{:056x}", hash);
	buf.put_slice(hex.as_bytes());
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use std::str::FromStr;
		use url::Url;

		let data = [(
			"trojan://password@127.0.0.1:22222",
			SettingsBuilder {
				addr: "127.0.0.1:22222".parse().unwrap(),
				password: "password".into(),
			},
		)];

		for (url, expected) in data {
			let url = Url::from_str(url).unwrap();
			let output = SettingsBuilder::parse_url(&url).unwrap();
			assert_eq!(expected, output);
		}
	}

	#[test]
	fn test_display_info() {
		use crate::protocol::DisplayInfo;
		let s = SettingsBuilder {
			password: "password".into(),
			addr: "localhost:12345".parse().unwrap(),
		};
		assert_eq!(s.brief().to_string(), "trojan-out");
		assert_eq!(s.detail().to_string(), "trojan-out(localhost:12345)");
	}
}
