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
use super::{Command, HeaderMode, Request};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpConnector, TcpStreamConnector},
		BytesStream, GetProtocolName, ProxyContext,
	},
	transport,
	utils::{crypto::aead::Algorithm, timestamp_now},
};
use rand::{rngs::OsRng, thread_rng};
use uuid::Uuid;

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
	pub transport: transport::outbound::SettingsBuilder,
}

impl SettingsBuilder {
	#[must_use]
	pub fn new(addr: SocksAddr, id: Uuid) -> Self {
		Self {
			addr,
			id,
			sec: SecurityType::default(),
			use_legacy_header: false,
			transport: transport::outbound::SettingsBuilder::default(),
		}
	}

	#[must_use]
	pub fn transport(mut self, transport: transport::outbound::SettingsBuilder) -> Self {
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
}

pub struct Settings {
	addr: SocksAddr,
	pub(super) id: Uuid,
	pub(super) sec: SecurityType,
	pub(super) header_mode: HeaderMode,
	transport: transport::outbound::Settings,
}

impl Settings {
	#[must_use]
	pub fn new(addr: SocksAddr, id: Uuid, transport: transport::outbound::Settings) -> Self {
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
		stream: BytesStream,
		dst: &'a SocksAddr,
	) -> Result<BytesStream, OutboundError> {
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

		let algo = match self.sec {
			SecurityType::Aes128Cfb => {
				return Err(Error::StreamEncryptionNotSupported.into());
			}
			SecurityType::Zero => {
				req.sec = SecurityType::None;
				req.opt.clear_chunk_stream();
				req.opt.clear_chunk_masking();
				let (r, w) = tcp::new_outbound_zero(stream.r, stream.w, req, &self.id, time, mode);
				return Ok(BytesStream::new(Box::new(r), Box::new(w)));
			}
			SecurityType::None => {
				let stream = tcp::new_outbound_plain(stream.r, stream.w, req, &self.id, time, mode);
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
			tcp::new_outbound_aead(stream.r, stream.w, req, &self.id, time, algo, mode)?;

		Ok(BytesStream::new(Box::new(read_half), Box::new(write_half)))
	}
}

impl GetProtocolName for Settings {
	#[inline]
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
	) -> Result<BytesStream, OutboundError> {
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
			BytesStream, ProxyContext,
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
			self.connect_stream(dst, stream.into(), context).await
		}

		async fn connect_stream<'a>(
			&'a self,
			dst: &'a SocksAddr,
			stream: BytesStream,
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
					let (read_half, write_half) = (stream.r, stream.w);

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
