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

mod tcp;
#[cfg(feature = "use-udp")]
mod udp;

use super::utils::{Error, SecurityType};
use super::{Command, HeaderMode, Request, PROTOCOL_NAME};
use crate::protocol::{AsyncReadWrite, BufBytesStream};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpConnector, TcpStreamConnector},
		GetProtocolName, ProxyContext,
	},
	transport,
	utils::{crypto::aead::Algorithm, timestamp_now},
};
use rand::{rngs::OsRng, thread_rng};
use uuid::Uuid;

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct SettingsBuilder {
	pub addr: SocksAddr,
	pub id: Uuid,
	pub sec: SecurityType,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub use_legacy_header: bool,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: transport::outbound::Builder,
}

impl SettingsBuilder {
	#[must_use]
	pub fn new(addr: SocksAddr, id: Uuid) -> Self {
		Self {
			addr,
			id,
			sec: SecurityType::default(),
			use_legacy_header: false,
			transport: transport::outbound::Builder::default(),
		}
	}

	#[must_use]
	pub fn transport(mut self, transport: transport::outbound::Builder) -> Self {
		self.transport = transport;
		self
	}

	#[must_use]
	pub fn sec(mut self, sec: SecurityType) -> Self {
		self.sec = sec;
		self
	}

	#[must_use]
	pub fn use_legacy_header(mut self, use_legacy: bool) -> Self {
		self.use_legacy_header = use_legacy;
		self
	}

	/// Creates a `VMess` outbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		let mode = if self.use_legacy_header {
			HeaderMode::Legacy
		} else {
			HeaderMode::Aead
		};
		Ok(Settings {
			addr: self.addr,
			id: self.id,
			sec: self.sec,
			header_mode: mode,
			transport: self.transport.build()?,
		})
	}

	/// Parse a URL with the format stated in 
	/// <https://github.com/v2fly/v2fly-github-io/issues/26>
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		fn make_ws_builder(url: &url::Url) -> transport::ws::OutboundBuilder {
			let mut path = None;
			let mut host = None;
			for (key, value) in url.query_pairs() {
				if key == "path" {
					path = Some(value);
				} else if key == "host" {
					host = Some(value);
				}
			}
			transport::ws::OutboundBuilder {
				headers: Default::default(),
				path: path.map_or_else(String::new, Into::into),
				host: host.map_or_else(String::new, Into::into),
				tls: None,
			}
		}

		let addr = crate::utils::url::get_socks_addr(url, None)?;

		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		let transport_str = url.username();
		let transport: transport::outbound::Builder = match transport_str {
			"tcp" => transport::outbound::Builder::default(),
			#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
			"tls" => transport::tls::OutboundBuilder::default().into(),
			#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
			"ws" => make_ws_builder(url).into(),
			#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
			"ws+tls" => {
				let mut builder = make_ws_builder(url);
				builder.tls = Some(transport::tls::OutboundBuilder::default());
				builder.into()
			}
			_ => return Err(format!("invalid transport string '{}'", transport_str).into()),
		};
		let uuid_authid = url.password().ok_or("VMess URL missing UUID")?;
		let (id_str, auth_id_num) = if uuid_authid.len() <= 36 {
			// UUID only
			(uuid_authid, 0)
		} else {
			let (id_str, auth_id_str) = uuid_authid.split_at(36);
			// Skip the first character '-'
			let auth_id_str = auth_id_str
				.strip_prefix('-')
				.ok_or_else(|| format!("invalid auth id format '{}'", auth_id_str))?;

			let auth_id_num = usize::from_str(auth_id_str)
				.map_err(|_| format!("cannot parse '{}' into usize", auth_id_str))?;
			(id_str, auth_id_num)
		};
		let id =
			Uuid::from_str(id_str).map_err(|e| format!("invalid UUID '{}' ({})", id_str, e))?;

		if auth_id_num > 0 {
			return Err("cannot use authid other than 0, only AEAD header is supported".into());
		}

		Ok(Self {
			addr,
			id,
			sec: SecurityType::Auto,
			use_legacy_header: false,
			transport,
		})
	}
}

pub struct Settings {
	addr: SocksAddr,
	pub(super) id: Uuid,
	pub(super) sec: SecurityType,
	pub(super) header_mode: HeaderMode,
	transport: transport::Outbound,
}

impl Settings {
	#[must_use]
	#[inline]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn TcpStreamConnector> {
		Some(self)
	}

	#[must_use]
	pub fn new(addr: SocksAddr, id: Uuid, transport: transport::Outbound) -> Self {
		Self {
			addr,
			id,
			sec: SecurityType::auto(),
			header_mode: HeaderMode::Aead,
			transport,
		}
	}

	async fn priv_connect<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
	) -> Result<BufBytesStream, OutboundError> {
		info!(
			"Creating VMess TCP connection to '{}', target: '{}'",
			&self.addr, dst
		);
		let time = timestamp_now();

		let mut rng = OsRng;
		let payload_key = rng.gen();
		let payload_iv = rng.gen();

		let mut req = Request::new(&payload_iv, &payload_key, dst.clone(), Command::Tcp);

		let mut rng = thread_rng();

		req.sec = self.sec;
		// padding, use a random number
		req.p = rng.next_u32().to_ne_bytes()[0] % 16;
		// verification code, use a random number
		req.v = rng.next_u32().to_ne_bytes()[0];

		trace!("Vmess request: {:?}", req);

		let mode = self.header_mode;

		let (rh, wh) = stream.split();
		let algo = match self.sec {
			SecurityType::Aes128Cfb => {
				return Err(Error::StreamEncryptionNotSupported.into());
			}
			SecurityType::Zero => {
				req.sec = SecurityType::None;
				req.opt.clear_chunk_stream();
				req.opt.clear_chunk_masking();
				let (r, w) = tcp::new_outbound_zero(rh, wh, req, &self.id, time, mode);
				return Ok(BufBytesStream::from_raw(Box::new(r), Box::new(w)));
			}
			SecurityType::None => {
				let stream = tcp::new_outbound_plain(rh, wh, req, &self.id, time, mode);
				return Ok(stream.into());
			}
			SecurityType::Aes128Gcm => Algorithm::Aes128Gcm,
			SecurityType::Chacha20Poly1305 => Algorithm::ChaCha20Poly1305,
			SecurityType::Auto => {
				if cfg!(target_arch = "x86") || cfg!(target_arch = "x86_64") {
					Algorithm::Aes128Gcm
				} else {
					Algorithm::ChaCha20Poly1305
				}
			}
		};

		// always enable chunk masking
		req.opt.set_chunk_masking();
		// always enable global padding
		req.opt.set_global_padding();

		let (read_half, write_half) =
			tcp::new_outbound_aead(rh, wh, req, &self.id, time, algo, mode)?;

		Ok(BufBytesStream::from_raw(
			Box::new(read_half),
			Box::new(write_half),
		))
	}
}

impl GetProtocolName for Settings {
	#[inline]
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
	) -> Result<BufBytesStream, OutboundError> {
		let stream = self.transport.connect(&self.addr, context).await?;
		Ok(self.priv_connect(stream, dst).await?)
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::{
		super::utils::{Error, SecurityType},
		tcp, udp, Settings,
	};
	use super::{Command, Request};
	use crate::{
		prelude::*,
		protocol::{
			self,
			outbound::{
				udp::{ConnectTunnelOverTcp, GetConnector, SocketOrTunnelStream},
				Error as OutboundError,
			},
			AsyncReadWrite, ProxyContext,
		},
		utils::{crypto::aead::Algorithm, timestamp_now},
	};
	use rand::{rngs::OsRng, thread_rng};

	impl GetConnector for Settings {
		fn get_udp_connector(&self) -> Option<protocol::outbound::udp::Connector<'_>> {
			let connector: Box<dyn ConnectTunnelOverTcp> =
				Box::new(UdpConnector { settings: self });
			return Some(protocol::outbound::udp::Connector::TunnelOverTcp(connector));
		}
	}

	struct UdpConnector<'a> {
		pub settings: &'a Settings,
	}

	#[async_trait]
	impl ConnectTunnelOverTcp for UdpConnector<'_> {
		async fn connect(
			&self,
			dst: &SocksAddr,
			context: &dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let stream = context.dial_tcp(&self.settings.addr).await?;
			self.connect_stream(dst, Box::new(stream), context).await
		}

		async fn connect_stream<'a>(
			&'a self,
			dst: &'a SocksAddr,
			stream: Box<dyn AsyncReadWrite>,
			_context: &'a dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let time = timestamp_now();

			let mut rng = OsRng;
			let payload_key = rng.gen();
			let payload_iv = rng.gen();

			let mut request = Request::new(&payload_iv, &payload_key, dst.clone(), Command::Udp);

			let mut rng = thread_rng();

			request.sec = self.settings.sec;
			// Padding, use a random number
			request.p = rng.next_u32().to_ne_bytes()[0] % 16;
			// Verification code, use a random number
			request.v = rng.next_u32().to_ne_bytes()[0];

			trace!("Vmess request: {:?}", request);

			let mode = self.settings.header_mode;

			let algo = match self.settings.sec {
				SecurityType::Aes128Cfb => return Err(Error::StreamEncryptionNotSupported.into()),
				SecurityType::Zero => return Err(Error::ZeroSecInUdp.into()),
				SecurityType::None => {
					let (read_half, write_half) = stream.split();

					let stream = tcp::new_outbound_plain(
						read_half,
						write_half,
						request,
						&self.settings.id,
						time,
						mode,
					);

					let stream = match stream {
						tcp::PlainStream::Masking((r, w)) => udp::new_udp_stream(r, w),
						tcp::PlainStream::NoMasking((r, w)) => udp::new_udp_stream(r, w),
					};
					return Ok(SocketOrTunnelStream::Tunnel(stream));
				}
				SecurityType::Aes128Gcm => Algorithm::Aes128Gcm,
				SecurityType::Chacha20Poly1305 | SecurityType::Auto => Algorithm::ChaCha20Poly1305,
			};

			// always enable chunk masking
			request.opt.set_chunk_masking();
			// always enable global padding
			request.opt.set_global_padding();

			let (read_half, write_half) = tokio::io::split(stream);

			let (read_half, write_half) = tcp::new_outbound_aead(
				read_half,
				write_half,
				request,
				&self.settings.id,
				time,
				algo,
				mode,
			)?;
			return Ok(SocketOrTunnelStream::Tunnel(udp::new_udp_stream(
				read_half, write_half,
			)));
		}
	}
}

#[cfg(test)]
mod tests {

	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use super::{SecurityType, SettingsBuilder};
		use crate::transport;
		use std::str::FromStr;
		use url::Url;

		let data = [
			(
				"vmess://tcp:2e09f64c-c967-4ce3-9498-fdcd8e39e04e-0@google.com:4433/?query=Value1#Connection2",
				SettingsBuilder {
					addr: "google.com:4433".parse().unwrap(),
					id: "2e09f64c-c967-4ce3-9498-fdcd8e39e04e".parse().unwrap(),
					sec: SecurityType::Auto,
					use_legacy_header: false,
					transport: Default::default(),
				},
			),
			(
				"vmess://ws+tls:7db04e8f-7cfc-46e0-9e18-d329c22ec353-0@myServer.com:12345/?path=%2FmyServerAddressPath%2F%E4%B8%AD%E6%96%87%E8%B7%AF%E5%BE%84%2F&host=www.myServer.com",
				SettingsBuilder {
					addr: "myServer.com:12345".parse().unwrap(),
					id: "7db04e8f-7cfc-46e0-9e18-d329c22ec353".parse().unwrap(),
					sec: SecurityType::Auto,
					use_legacy_header: false,
					transport: transport::outbound::Builder::Ws(transport::ws::OutboundBuilder {
						headers: Default::default(),
						path: "/myServerAddressPath/中文路径/".into(),
						host: "www.myServer.com".into(),
						tls: Some(transport::tls::OutboundBuilder {
							alpns: Vec::new(),
							ca_file: None,
						}),
					}),
				},
			),
		];

		for (url, expected) in data {
			let url = Url::from_str(url).unwrap();
			let output = SettingsBuilder::parse_url(&url).unwrap();
			assert_eq!(expected, output);
		}
	}
}
