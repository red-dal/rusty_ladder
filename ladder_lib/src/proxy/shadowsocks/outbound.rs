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

use super::{method_to_algo, password_to_key, tcp, utils::salt_len, Method, PROTOCOL_NAME};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, StreamConnector, StreamFunc},
		AsyncReadWrite, BufBytesStream, GetProtocolName, ProxyContext,
	},
	utils::{crypto::aead::Algorithm, LazyWriteHalf},
};
use bytes::Bytes;
use rand::rngs::OsRng;
use tokio::io::BufReader;

// -------------------------------------------------------------------------
//                              Builder
// -------------------------------------------------------------------------

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	pub addr: SocksAddr,
	pub method: Method,
	pub password: String,
}

impl SettingsBuilder {
	/// Creates a Shadowsocks outbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(Settings::new(self.addr, &self.password, self.method))
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// ss://userinfo@host:port
	/// ```
	/// `userinfo` is `base64("method:password")`,
	///
	/// where `method` must be one of
	/// "none", "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305".
	///
	/// Read more at <https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html>
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;
		let (method, password) = super::utils::get_method_password(url)?;
		let addr = crate::utils::url::get_socks_addr(url, None)?;
		Ok(Self {
			addr,
			method,
			password,
		})
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ss-out")
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let addr = &self.addr;
		if Method::None == self.method {
			write!(f, "ss-out-none({addr})")
		} else {
			let method = self.method.as_str();
			write!(f, "ss-out-{method}({addr})")
		}
	}
}

// -------------------------------------------------------------------------
//                              Settings
// -------------------------------------------------------------------------

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct EncryptionSettings {
	pub password: Bytes,
	pub algo: Algorithm,
}

pub struct Settings {
	addr: SocksAddr,
	inner: Option<EncryptionSettings>,
}

impl Settings {
	#[must_use]
	#[inline]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn StreamConnector> {
		Some(self)
	}

	fn priv_connect<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
	) -> Result<BufBytesStream, OutboundError> {
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

			crypt_write
				.encoder
				.encode_into_lazy(&addr_buf)
				.map_err(OutboundError::Protocol)?;

			trace!("Shadowsocks request sent");
			Ok(BufBytesStream {
				r: Box::new(crypt_read),
				w: Box::new(crypt_write),
			})
		} else {
			// Without encryption
			let mut addr_buf = Vec::with_capacity(dst.serialized_len_atyp());
			dst.write_to(&mut addr_buf);
			let (r, w) = stream.split();
			let write_half = LazyWriteHalf::new(w, addr_buf);
			Ok(BufBytesStream::new(
				Box::new(BufReader::new(r)),
				Box::new(write_half),
			))
		}
	}
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[async_trait]
impl StreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream_func: Box<StreamFunc<'a>>,
		dst: SocksAddr,
		context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		let stream = stream_func(self.addr.clone(), context).await?;
		self.priv_connect(stream, &dst)
	}
}

impl Settings {
	#[must_use]
	pub fn new(addr: SocksAddr, password: &str, method: Method) -> Self {
		let inner = method_to_algo(method).map(|algo| EncryptionSettings {
			password: password_to_key(salt_len(algo), password),
			algo,
		});
		Self { addr, inner }
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::{super::udp, OutboundError, ProxyContext, Settings};
	use crate::protocol::{
		self,
		outbound::udp::{
			socket::{DatagramStream, UdpSocketWrapper},
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
				DatagramStream {
					read_half: Box::new(read_half),
					write_half: Box::new(write_half),
				},
				context,
			)
			.await
		}

		async fn connect_socket_stream<'a>(
			&'a self,
			stream: DatagramStream,
			_context: &'a dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let (read_half, write_half) = (stream.read_half, stream.write_half);
			#[allow(clippy::option_if_let_else)]
			if let Some(inner) = &self.settings.inner {
				// With encryption
				let read_half = udp::ReadHalf::new(read_half, inner.algo, inner.password.clone());
				let write_half = udp::WriteHalf::new(
					write_half,
					inner.algo,
					self.settings.addr.clone(),
					inner.password.clone(),
				);
				Ok(SocketOrTunnelStream::Socket(DatagramStream {
					read_half: Box::new(read_half),
					write_half: Box::new(write_half),
				}))
			} else {
				// Without encryption
				let read_half = udp::PlainReadHalf::new(read_half);
				let write_half = udp::PlainWriteHalf::new(write_half, self.settings.addr.clone());
				Ok(SocketOrTunnelStream::Socket(DatagramStream {
					read_half: Box::new(read_half),
					write_half: Box::new(write_half),
				}))
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use super::{Method, SettingsBuilder};
		use std::str::FromStr;
		use url::Url;

		let data = [(
			"ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1",
			SettingsBuilder {
				method: Method::Aes128Gcm,
				password: "test".to_owned(),
				addr: "192.168.100.1:8888".parse().unwrap(),
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

		let mut s = SettingsBuilder {
			addr: "localhost:12345".parse().unwrap(),
			method: Method::None,
			password: "password".into(),
		};
		// Method::None
		assert_eq!(s.brief().to_string(), "ss-out");
		assert_eq!(s.detail().to_string(), "ss-out-none(localhost:12345)");
		// Method::Aes128Gcm
		s.method = Method::Aes128Gcm;
		assert_eq!(s.brief().to_string(), "ss-out");
		assert_eq!(s.detail().to_string(), "ss-out-aes128gcm(localhost:12345)");
		// Method::Aes256Gcm
		s.method = Method::Aes256Gcm;
		assert_eq!(s.brief().to_string(), "ss-out");
		assert_eq!(s.detail().to_string(), "ss-out-aes256gcm(localhost:12345)");
		// Method::Chacha20Poly1305
		s.method = Method::Chacha20Poly1305;
		assert_eq!(s.brief().to_string(), "ss-out");
		assert_eq!(
			s.detail().to_string(),
			"ss-out-chacha20poly1305(localhost:12345)"
		);
	}
}
