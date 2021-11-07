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

use super::{method_to_algo, password_to_key, tcp, utils::salt_len, Method};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpConnector, TcpStreamConnector},
		BytesStream, GetProtocolName, ProxyContext,
	},
	transport,
	utils::{crypto::aead::Algorithm, LazyWriteHalf},
};
use bytes::Bytes;
use rand::rngs::OsRng;

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	pub addr: SocksAddr,
	pub method: Method,
	pub password: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: transport::outbound::SettingsBuilder,
}

impl SettingsBuilder {
	/// Creates a Shadowsocks outbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(Settings::new(
			self.addr,
			&self.password,
			self.method,
			self.transport.build()?,
		))
	}
}

struct EncryptionSettings {
	pub password: Bytes,
	pub algo: Algorithm,
}

pub struct Settings {
	addr: SocksAddr,
	inner: Option<EncryptionSettings>,
	transport: transport::outbound::Settings,
}

impl Settings {
	async fn priv_connect<'a>(
		&'a self,
		stream: BytesStream,
		dst: &'a SocksAddr,
	) -> Result<BytesStream, OutboundError> {
		debug!(
			"Creating Shadowsocks connection to '{}', target: '{}'",
			&self.addr, dst
		);

		if let Some(s) = &self.inner {
			// With encryption
			let local_salt = {
				let mut salt = vec![0_u8; salt_len(s.algo)];
				// very unlikely to generate a used salt with the OS RNG.
				OsRng.fill_bytes(&mut salt);
				salt
			};

			let (crypt_read, mut crypt_write) =
				tcp::new_crypt_stream(stream, s.algo, s.password.clone(), local_salt);

			trace!("Trying to send shadowsocks request to {}", dst);
			let mut addr_buf = Vec::with_capacity(dst.serialized_len_atyp());
			dst.write_to(&mut addr_buf);

			// crypt_write.encode_into_buffer(&addr_buf)?;
			// crypt_write.write_all(&mut addr_buf).await?;
			crypt_write
				.encoder
				.encode_into_lazy(&addr_buf)
				.map_err(OutboundError::Protocol)?;

			trace!("Shadowsocks request sent");
			Ok(BytesStream::new(
				Box::new(crypt_read),
				Box::new(crypt_write),
			))
		} else {
			// Without encryption
			let mut addr_buf = Vec::with_capacity(dst.serialized_len_atyp());
			dst.write_to(&mut addr_buf);
			let write_half = LazyWriteHalf::new_not_lazy(stream.w, addr_buf);
			Ok(BytesStream::new(Box::new(stream.r), Box::new(write_half)))
		}
	}
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		super::PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpStreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream: BytesStream,
		dst: &'a SocksAddr,
		_context: &'a dyn ProxyContext,
	) -> Result<BytesStream, OutboundError> {
		let stream = self.transport.connect_stream(stream, &self.addr).await?;
		self.priv_connect(stream, dst).await
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
	) -> Result<BytesStream, OutboundError> {
		let stream = self.transport.connect(&self.addr, context).await?;
		self.priv_connect(stream, dst).await
	}
}

impl Settings {
	#[must_use]
	pub fn new(
		addr: SocksAddr,
		password: &str,
		method: Method,
		transport: transport::outbound::Settings,
	) -> Self {
		let inner = method_to_algo(method).map(|algo| EncryptionSettings {
			password: password_to_key(salt_len(algo), password),
			algo,
		});
		Self {
			addr,
			inner,
			transport,
		}
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::{super::udp, OutboundError, ProxyContext, Settings};
	use crate::protocol::{
		self,
		outbound::udp::{
			socket::{PacketStream, UdpSocketWrapper},
			ConnectSocket, GetConnector, SocketOrTunnelStream,
		},
	};
	use async_trait::async_trait;
	use std::net::SocketAddr;

	impl GetConnector for Settings {
		fn get_udp_connector(&self) -> Option<protocol::outbound::udp::Connector<'_>> {
			Some(protocol::outbound::udp::Connector::Socket(Box::new(
				UdpConnector { settings: self },
			)))
		}
	}

	struct UdpConnector<'a> {
		settings: &'a Settings,
	}

	#[async_trait]
	impl ConnectSocket for UdpConnector<'_> {
		async fn connect_socket(
			&self,
			context: &dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let read_half = UdpSocketWrapper::bind(SocketAddr::new([0, 0, 0, 0].into(), 0)).await?;
			let write_half = read_half.clone();
			self.connect_socket_stream(
				PacketStream {
					read_half: Box::new(read_half),
					write_half: Box::new(write_half),
				},
				context,
			)
			.await
		}

		async fn connect_socket_stream<'a>(
			&'a self,
			stream: PacketStream,
			_context: &'a dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			#[allow(clippy::option_if_let_else)]
			if let Some(inner) = &self.settings.inner {
				// With encryption
				let (read_half, write_half) = (stream.read_half, stream.write_half);
				let read_half = udp::ReadHalf::new(read_half, inner.algo, inner.password.clone());
				let write_half = udp::WriteHalf::new(
					write_half,
					inner.algo,
					self.settings.addr.clone(),
					inner.password.clone(),
				);
				Ok(SocketOrTunnelStream::Socket(PacketStream {
					read_half: Box::new(read_half),
					write_half: Box::new(write_half),
				}))
			} else {
				// Without encryption
				let (read_half, write_half) = (stream.read_half, stream.write_half);
				let read_half = udp::PlainReadHalf::new(read_half);
				let write_half = udp::PlainWriteHalf::new(write_half, self.settings.addr.clone());
				Ok(SocketOrTunnelStream::Socket(PacketStream {
					read_half: Box::new(read_half),
					write_half: Box::new(write_half),
				}))
			}
		}
	}
}
