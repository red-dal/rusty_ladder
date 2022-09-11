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
	network,
	prelude::*,
	protocol::{
		inbound::{AcceptError, Handshake, SessionInfo, StreamAcceptor},
		AsyncReadWrite, DisplayInfo, GetProtocolName,
	},
	utils::OneOrMany,
};

//-----------------------------------
//               Details
//-----------------------------------

#[ladder_lib_macro::impl_variants(Details)]
mod details {
	use crate::{
		protocol::{
			inbound::{AcceptError, Handshake, SessionInfo, StreamAcceptor},
			AsyncReadWrite, GetProtocolName, Network,
		},
		proxy,
	};
	use async_trait::async_trait;

	pub enum Details {
		Tunnel(proxy::tunnel::Settings),
		#[cfg(feature = "socks5-inbound")]
		Socks5(proxy::socks5::inbound::Settings),
		#[cfg(feature = "http-inbound")]
		Http(proxy::http::inbound::Settings),
		#[cfg(any(
			feature = "shadowsocks-inbound-openssl",
			feature = "shadowsocks-inbound-ring"
		))]
		Shadowsocks(proxy::shadowsocks::inbound::Settings),
		#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
		Vmess(proxy::vmess::inbound::Settings),
		#[cfg(feature = "trojan-inbound")]
		Trojan(proxy::trojan::inbound::Settings),
	}

	impl GetProtocolName for Details {
		#[implement]
		fn protocol_name(&self) -> &'static str {}
		#[implement]
		fn network(&self) -> Network {}
	}

	#[async_trait]
	impl StreamAcceptor for Details {
		#[implement]
		async fn accept_stream<'a>(
			&'a self,
			stream: Box<dyn AsyncReadWrite>,
			info: SessionInfo,
		) -> Result<Handshake<'a>, AcceptError> {
		}
	}
}
use details::Details;

#[cfg(feature = "use-udp")]
impl Details {
	#[must_use]
	pub fn get_udp_acceptor(
		&self,
	) -> Option<&(dyn crate::protocol::inbound::udp::Acceptor + Send + Sync)> {
		#[allow(clippy::match_wildcard_for_single_variants)]
		match self {
			Self::Tunnel(s) => {
				if s.network().use_udp() {
					Some(s)
				} else {
					None
				}
			}
			#[allow(unreachable_patterns)]
			_ => None,
		}
	}
}

#[ladder_lib_macro::impl_variants(DetailsBuilder)]
mod details_builder {
	use super::Details;
	use crate::{prelude::BoxStdErr, proxy};

	#[derive(Debug)]
	#[cfg_attr(
		feature = "use_serde",
		derive(serde::Deserialize),
		serde(rename_all = "lowercase", tag = "protocol")
	)]
	pub enum DetailsBuilder {
		Tunnel(proxy::tunnel::Settings),
		#[cfg(feature = "socks5-inbound")]
		Socks5(proxy::socks5::inbound::SettingsBuilder),
		#[cfg(feature = "http-inbound")]
		Http(proxy::http::inbound::SettingsBuilder),
		#[cfg(any(
			feature = "shadowsocks-inbound-openssl",
			feature = "shadowsocks-inbound-ring"
		))]
		Shadowsocks(proxy::shadowsocks::inbound::SettingsBuilder),
		#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
		Vmess(proxy::vmess::inbound::SettingsBuilder),
		#[cfg(feature = "trojan-inbound")]
		Trojan(proxy::trojan::inbound::SettingsBuilder),
	}

	impl DetailsBuilder {
		/// Create a new [`Details`].
		///
		/// # Errors
		///
		/// Returns an error if the inner type failed to build.
		#[implement(map_into)]
		pub fn build(self) -> Result<Details, BoxStdErr> {}
	}

	impl crate::protocol::DisplayInfo for DetailsBuilder {
		#[implement]
		fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {}
		#[implement]
		fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {}
	}
}
pub use details_builder::DetailsBuilder;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub enum ErrorPolicy {
	#[cfg_attr(feature = "use_serde", serde(rename = "drop"))]
	Drop,
	#[cfg_attr(feature = "use_serde", serde(rename = "silent_drop"))]
	SilentDrop,
}

impl Default for ErrorPolicy {
	fn default() -> Self {
		Self::SilentDrop
	}
}

//-----------------------------------
//               Inbound
//-----------------------------------

pub struct Inbound {
	pub tag: Tag,
	pub network: network::Config,
	pub err_policy: ErrorPolicy,
	settings: Details,
	transport: crate::transport::Inbound,
}

impl Inbound {
	#[inline]
	#[must_use]
	pub fn protocol_name(&self) -> &'static str {
		self.settings.protocol_name()
	}
}

impl GetProtocolName for Inbound {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		self.settings.protocol_name()
	}
}

#[async_trait]
impl StreamAcceptor for Inbound {
	async fn accept_stream<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		info: SessionInfo,
	) -> Result<Handshake<'a>, AcceptError> {
		let stream = self.transport.accept(stream).await?;
		let mut info = info;
		info.is_transport_empty = matches!(&self.transport, crate::transport::Inbound::None(_));
		self.settings.accept_stream(stream, info).await
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::Inbound;
	use crate::{network, protocol::inbound::udp::DatagramStream, server::Error};
	use futures::Future;
	use std::net::SocketAddr;

	pub trait UdpCallback: Send + Sync {
		type Fut: Future<Output = Result<(), Error>> + Send;

		fn run(&self, local_addr: &SocketAddr, ds: DatagramStream) -> Self::Fut;
	}

	impl Inbound {
		/// Accept and handle datagram forever.
		///
		/// # Errors
		///
		/// Returns an [`Error`] if there are any invalid configurations or IO errors.
		///
		/// Errors occurred in `callback` will not return an [`Error`].
		pub async fn serve_datagram<C>(&self, callback: C) -> Result<(), Error>
		where
			C: UdpCallback,
		{
			if let Some(acceptor) = self.settings.get_udp_acceptor() {
				#[allow(irrefutable_let_patterns)]
				let bind_addrs = if let network::Config::Net(conf) = &self.network {
					&conf.addr
				} else {
					let msg = format!(
						"Inbound {} '{}' wants UDP, but network is not raw",
						self.protocol_name(),
						self.tag
					);
					return Err(Error::Other(msg.into()));
				};
				let mut tasks = Vec::new();
				for local_addr in bind_addrs.as_slice() {
					let socket = tokio::net::UdpSocket::bind(local_addr)
						.await
						.map_err(|e| Error::Other(e.into()))?;
					let ds = acceptor.accept_udp(socket).await.map_err(Error::Other)?;
					let task = callback.run(local_addr, ds);
					tasks.push(task);
				}
				futures::future::try_join_all(tasks).await?;
			}
			Ok(())
		}
	}
}
#[cfg(feature = "use-udp")]
pub use udp_impl::UdpCallback;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "use_serde", serde(rename_all = "lowercase"))]
pub enum NetworkType {
	Net,
}

impl Default for NetworkType {
	#[inline]
	fn default() -> Self {
		NetworkType::Net
	}
}

// ========================= Builder ========================

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Builder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tag: Tag,
	pub addr: OneOrMany<smol_str::SmolStr>,
	#[cfg_attr(feature = "use_serde", serde(flatten))]
	pub settings: DetailsBuilder,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub err_policy: ErrorPolicy,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub network_type: NetworkType,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: crate::transport::inbound::Builder,
}

impl Builder {
	/// Creates a [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if `self.settings` failed to build.
	#[inline]
	pub fn build(self) -> Result<Inbound, BoxStdErr> {
		let network = match self.network_type {
			NetworkType::Net => {
				let addr: Result<Vec<SocketAddr>, String> = self
					.addr
					.into_iter()
					.map(|s| {
						SocketAddr::from_str(s.as_str())
							.map_err(|e| format!("invalid address '{}' ({})", s, e))
					})
					.collect();
				network::Config::Net(network::NetConfig { addr: addr? })
			}
		};
		Ok(Inbound {
			tag: self.tag,
			settings: self.settings.build()?,
			network,
			err_policy: self.err_policy,
			transport: self.transport.build()?,
		})
	}

	/// Parse a URL into [`Builder`].
	///
	/// # Errors
	/// Return an error if
	/// - `url` scheme does not match any of the protocol names
	/// - `url` host is not an IP address
	/// - the protocol does not support URL parsing
	/// - `url` does not match the protocol's format
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		use crate::proxy;
		type ParseFunc = Box<dyn Fn(&url::Url) -> Result<DetailsBuilder, BoxStdErr>>;

		let port = url.port().ok_or("URL must have a port")?;
		let host = url.host().ok_or("URL must have a host")?;
		let ip: std::net::IpAddr = match host {
			url::Host::Domain(s) => s
				.parse()
				.map_err(|_| format!("URL host '{}' must be an IP", s))?,
			url::Host::Ipv4(ip) => ip.into(),
			url::Host::Ipv6(ip) => ip.into(),
		};
		let addr = SocketAddr::new(ip, port);

		let mut parse_url_map = std::collections::HashMap::<&str, ParseFunc>::new();
		// Tunnel
		parse_url_map.insert(
			proxy::tunnel::PROTOCOL_NAME,
			Box::new(|url| proxy::tunnel::Settings::parse_url(url).map(Into::into)),
		);
		// SOCKS5
		#[cfg(feature = "socks5-inbound")]
		{
			use proxy::socks5::{inbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| SettingsBuilder::parse_url(url).map(Into::into)),
			);
		}
		// HTTP
		#[cfg(feature = "http-inbound")]
		{
			use proxy::http::{inbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| SettingsBuilder::parse_url(url).map(Into::into)),
			);
		}
		// SS
		#[cfg(any(
			feature = "shadowsocks-inbound-openssl",
			feature = "shadowsocks-inbound-ring"
		))]
		{
			use proxy::shadowsocks::{inbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| SettingsBuilder::parse_url(url).map(Into::into)),
			);
		}
		let parse_url = parse_url_map.get(url.scheme()).ok_or_else(|| {
			let valid_options = parse_url_map.keys().collect::<Vec<_>>();
			format!(
				"unknown protocol '{}', must be one of {}",
				url.scheme(),
				crate::utils::ListDisplay(valid_options.as_slice())
			)
		})?;
		let settings = parse_url(url)?;
		Ok(Self {
			tag: url.fragment().map(Into::into).unwrap_or_default(),
			addr: OneOrMany::new_one(Tag::from(addr.to_string())),
			settings,
			err_policy: Default::default(),
			network_type: Default::default(),
			transport: Default::default(),
		})
	}
}

impl DisplayInfo for Builder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"['{tag}'|{brief}",
			tag = &self.tag,
			brief = &self.settings.brief(),
		)?;
		if self.transport.is_empty() {
			f.write_str("]")
		} else {
			write!(f, "|{}]", self.transport.brief())
		}
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"['{tag}'|{brief}",
			tag = &self.tag,
			brief = &self.settings.detail(),
		)?;
		if self.transport.is_empty() {
			f.write_str("]")
		} else {
			write!(f, "|{}]", self.transport.detail())
		}
	}
}
