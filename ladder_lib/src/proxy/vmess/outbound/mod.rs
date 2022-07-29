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

use super::utils::{SecurityType, SecurityTypeBuilder};
use super::{Command, HeaderMode, Request, PROTOCOL_NAME};
use crate::protocol::outbound::StreamFunc;
use crate::protocol::{AsyncReadWrite, BufBytesStream};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpStreamConnector},
		GetProtocolName, ProxyContext,
	},
	utils::{crypto::aead::Algorithm, timestamp_now},
};
use rand::{rngs::OsRng, thread_rng};
use uuid::Uuid;

// -----------------------------------------------------------
//                         Builder
// -----------------------------------------------------------

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
	pub sec: SecurityTypeBuilder,
	/// Use legacy request header instead of AEAD header.
	/// This is no longer supported.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub use_legacy_header: bool,
}

impl SettingsBuilder {
	#[must_use]
	pub fn new(addr: SocksAddr, id: Uuid) -> Self {
		Self {
			addr,
			id,
			sec: SecurityTypeBuilder::default(),
			use_legacy_header: false,
		}
	}

	#[must_use]
	pub fn sec(mut self, sec: SecurityTypeBuilder) -> Self {
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
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		let mode = if self.use_legacy_header {
			return Err("legacy auth is not supported".into());
		} else {
			HeaderMode::Aead
		};
		let sec = match self.sec {
			SecurityTypeBuilder::Aes128Cfb => {
				return Err("stream encryption is not supported".into())
			}
			SecurityTypeBuilder::Auto => SecurityType::auto(),
			SecurityTypeBuilder::Aes128Gcm => SecurityType::Aes128Gcm,
			SecurityTypeBuilder::Chacha20Poly1305 => SecurityType::Chacha20Poly1305,
			SecurityTypeBuilder::None => SecurityType::None,
			SecurityTypeBuilder::Zero => SecurityType::Zero,
		};
		Ok(Settings {
			addr: self.addr,
			id: self.id,
			sec,
			header_mode: mode,
		})
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("vmess-out")
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let addr = &self.addr;
		let id = super::utils::PartialId(&self.id);
		let sec = match self.sec {
			SecurityTypeBuilder::Aes128Cfb => "aes128cfb",
			SecurityTypeBuilder::Auto => "auto",
			SecurityTypeBuilder::Aes128Gcm => "aes128gcm",
			SecurityTypeBuilder::Chacha20Poly1305 => "chacha20poly1305",
			SecurityTypeBuilder::None => "none",
			SecurityTypeBuilder::Zero => "zero",
		};
		write!(f, "vmess-out(add:'{addr}',id:{id}*,sec:{sec})")
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_display_info() {
		use crate::protocol::DisplayInfo;

		let s = SettingsBuilder {
			addr: "not.localhost:12345".parse().unwrap(),
			id: "87b35ca4-ff27-4c28-9a8d-01a0148ec4b6".parse().unwrap(),
			sec: SecurityTypeBuilder::None,
			use_legacy_header: false,
		};

		assert_eq!(s.brief().to_string(), "vmess-out");
		assert_eq!(
			s.detail().to_string(),
			"vmess-out(add:'not.localhost:12345',id:87b3*,sec:none)"
		);
	}
}

#[cfg(feature = "parse-url")]
mod parse_url_impl;

// -----------------------------------------------------------
//                         Settings
// -----------------------------------------------------------

pub struct Settings {
	addr: SocksAddr,
	pub(super) id: Uuid,
	pub(super) sec: SecurityType,
	pub(super) header_mode: HeaderMode,
}

impl Settings {
	#[must_use]
	#[inline]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn TcpStreamConnector> {
		Some(self)
	}

	#[must_use]
	pub fn new(addr: SocksAddr, id: Uuid) -> Self {
		Self {
			addr,
			id,
			sec: SecurityType::auto(),
			header_mode: HeaderMode::Aead,
		}
	}

	async fn priv_connect<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
	) -> Result<BufBytesStream, OutboundError> {
		debug!(
			"Creating VMess TCP connection to server '{}', dst: '{}'",
			&self.addr, dst
		);
		let time = timestamp_now();

		let mut rng = OsRng;
		let payload_key = rng.gen();
		let payload_iv = rng.gen();

		let mut req = Request::new(&payload_iv, &payload_key, dst.clone(), Command::Tcp);

		let mut rng = thread_rng();

		req.sec = self.sec;
		// padding, use a random 4-bit number
		req.p = rng.gen_range(0..16);
		// verification code, use a random 1-byte number
		req.v = rng.gen();

		trace!("Vmess request: {:?}", req);

		let mode = self.header_mode;

		let (rh, wh) = stream.split();
		let algo = match self.sec {
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
		stream_func: Box<StreamFunc<'a>>,
		dst: SocksAddr,
		context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		let stream = stream_func(self.addr.clone(), context).await?;
		self.priv_connect(stream, &dst).await
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
			// Padding, use a random 4-bit number
			request.p = rng.gen_range(0..16);
			// Verification code, use a random 1-byte number
			request.v = rng.gen();

			trace!("Vmess request: {:?}", request);

			let mode = self.settings.header_mode;

			let algo = match self.settings.sec {
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
				SecurityType::Chacha20Poly1305 => Algorithm::ChaCha20Poly1305,
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
