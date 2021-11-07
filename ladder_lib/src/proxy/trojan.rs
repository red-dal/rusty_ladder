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
		GetProtocolName, OutboundError, ProxyContext, ProxyStream, TcpConnector, TcpStreamConnector,
	},
	transport,
	utils::LazyWriteHalf,
};
use async_trait::async_trait;
use sha2::{Digest, Sha224};

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	pub password: String,
	pub addr: SocksAddr,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: transport::outbound::SettingsBuilder,
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
			transport: self.transport.build()?,
		})
	}
}

pub struct Settings {
	password: String,
	addr: SocksAddr,
	transport: transport::outbound::Settings,
}

impl Settings {
	async fn priv_connect<'a>(
		&'a self,
		stream: ProxyStream,
		dst: &'a SocksAddr,
	) -> Result<ProxyStream, OutboundError> {
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

		let write_half = LazyWriteHalf::new_not_lazy(stream.w, req_buf);
		let stream = ProxyStream::new(stream.r, Box::new(write_half));
		Ok(stream)
	}
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		"trojan"
	}
}

#[async_trait]
impl TcpStreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream: ProxyStream,
		dst: &'a SocksAddr,
		_context: &'a dyn ProxyContext,
	) -> Result<ProxyStream, OutboundError> {
		let stream = self.transport.connect_stream(stream, &self.addr).await?;
		Ok(self.priv_connect(stream, dst).await?)
	}

	#[inline]
	fn addr(&self) -> &SocksAddr {
		&self.addr
	}
}

#[async_trait]
impl TcpConnector for Settings {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<ProxyStream, OutboundError> {
		let stream = self.transport.connect(&self.addr, context).await?;
		Ok(self.priv_connect(stream, dst).await?)
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::{password_to_hex, Command, Settings};
	use crate::{
		prelude::*,
		protocol::{
			self,
			outbound::socket::{UdpProxyStream, UdpRecv, UdpSend},
			socks_addr::ReadError,
			BoxRead, ConnectUdpOverTcpSocket, GetConnector, OutboundError, ProxyContext,
			ProxyStream, UdpSocketOrTunnelStream,
		},
		utils::{read_u16, LazyWriteHalf},
	};
	use async_trait::async_trait;
	use std::io;

	impl GetConnector for Settings {
		fn get_udp_connector(&self) -> Option<protocol::outbound::UdpConnector<'_>> {
			return Some(protocol::outbound::UdpConnector::SocketOverTcp(Box::new(
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
	impl UdpRecv for UdpReadHalf {
		async fn recv_src(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocksAddr)> {
			debug_assert!(buf.len() > 4 * 1024);
			let src = SocksAddr::async_read_from(&mut self.inner)
				.await
				.map_err(|e| {
					if let ReadError::Io(e) = e {
						e
					} else {
						io::Error::new(io::ErrorKind::InvalidData, e)
					}
				})?;

			let mut tmp = [0_u8; 4];
			self.inner.read_exact(&mut tmp).await?;

			let (len, crlf) = tmp.split_at(2);

			let len = read_u16(len) as usize;

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
	impl<W: AsyncWrite + Unpin + Send + Sync> UdpSend for UdpWriteHalf<W> {
		async fn send_dst(&mut self, dst: &SocksAddr, payload: &[u8]) -> std::io::Result<usize> {
			let payload_len = u16::try_from(payload.len()).unwrap_or_else(|_| {
				info!(
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
	impl ConnectUdpOverTcpSocket for UdpConnector<'_> {
		async fn connect(
			&self,
			context: &dyn ProxyContext,
		) -> Result<UdpSocketOrTunnelStream, OutboundError> {
			let stream = context.dial_tcp(&self.settings.addr).await?;
			self.connect_stream(stream.into(), context).await
		}

		async fn connect_stream<'a>(
			&'a self,
			stream: ProxyStream,
			_context: &'a dyn ProxyContext,
		) -> Result<UdpSocketOrTunnelStream, OutboundError> {
			let stream = self
				.settings
				.transport
				.connect_stream(stream, &self.settings.addr)
				.await?;

			let mut req_buf = Vec::with_capacity(512);
			password_to_hex(self.settings.password.as_bytes(), &mut req_buf);
			req_buf.put_slice(CRLF);
			req_buf.put_u8(Command::UdpAssociate as u8);
			// dummy address
			self.settings.addr.write_to(&mut req_buf);
			req_buf.put_slice(CRLF);

			let write_half = LazyWriteHalf::new_not_lazy(stream.w, req_buf);

			let read_half = UdpReadHalf::new(stream.r);
			let write_half = UdpWriteHalf::new(write_half);

			return Ok(UdpSocketOrTunnelStream::Socket(UdpProxyStream {
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
