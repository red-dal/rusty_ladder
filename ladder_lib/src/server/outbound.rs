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

#[cfg(feature = "use-udp")]
use crate::protocol::outbound::udp;
use crate::{
	prelude::*,
	protocol::{
		outbound::{Connector, Error as OutboundError, StreamConnector, StreamFunc},
		BufBytesStream, GetProtocolName, ProxyContext,
	},
};
use futures::FutureExt;

// -------------------------------------------------
//                   Details
// -------------------------------------------------

#[ladder_lib_macro::impl_variants(Details)]
mod details {
	use super::OutboundError;
	use crate::{
		protocol::{
			outbound::{StreamConnector, StreamFunc},
			BufBytesStream, GetProtocolName, ProxyContext, SocksAddr,
		},
		proxy,
	};
	use async_trait::async_trait;
	use std::sync::Arc;

	pub enum Details {
		Freedom(Arc<proxy::freedom::Settings>),
		#[cfg(feature = "socks5-outbound")]
		Socks5(Arc<proxy::socks5::outbound::Settings>),
		#[cfg(feature = "http-outbound")]
		Http(Arc<proxy::http::outbound::Settings>),
		#[cfg(any(
			feature = "shadowsocks-outbound-openssl",
			feature = "shadowsocks-outbound-ring"
		))]
		Shadowsocks(Arc<proxy::shadowsocks::outbound::Settings>),
		#[cfg(feature = "trojan-outbound")]
		Trojan(Arc<proxy::trojan::outbound::Settings>),
		#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
		Vmess(Arc<proxy::vmess::outbound::Settings>),
		#[cfg(feature = "chain-outbound")]
		Chain(Arc<proxy::chain::Settings>),
	}

	impl GetProtocolName for Details {
		#[implement]
		fn protocol_name(&self) -> &'static str {}
	}

	#[async_trait]
	impl StreamConnector for Details {
		#[implement]
		async fn connect_stream<'a>(
			&'a self,
			stream_func: Box<StreamFunc<'a>>,
			dst: SocksAddr,
			context: &'a dyn ProxyContext,
		) -> Result<BufBytesStream, OutboundError> {
		}
	}

	#[cfg(feature = "use-udp")]
	use crate::protocol::outbound::udp;

	#[cfg(feature = "use-udp")]
	impl udp::GetConnector for Details {
		#[implement]
		fn get_udp_connector(&self) -> Option<udp::Connector<'_>> {}
	}
}

pub use details::Details;

#[ladder_lib_macro::impl_variants(DetailsBuilder)]
mod details_builder {
	use super::Details;
	use crate::{prelude::BoxStdErr, proxy};

	#[derive(Debug)]
	#[cfg_attr(
		feature = "use_serde",
		derive(serde::Deserialize),
		serde(tag = "protocol", rename_all = "lowercase")
	)]
	pub enum DetailsBuilder {
		Freedom(proxy::freedom::Settings),
		#[cfg(feature = "socks5-outbound")]
		Socks5(proxy::socks5::outbound::SettingsBuilder),
		#[cfg(feature = "http-outbound")]
		Http(proxy::http::outbound::SettingsBuilder),
		#[cfg(any(
			feature = "shadowsocks-outbound-openssl",
			feature = "shadowsocks-outbound-ring"
		))]
		Shadowsocks(proxy::shadowsocks::outbound::SettingsBuilder),
		#[cfg(feature = "trojan-outbound")]
		Trojan(proxy::trojan::outbound::SettingsBuilder),
		#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
		Vmess(proxy::vmess::outbound::SettingsBuilder),
		#[cfg(feature = "chain-outbound")]
		Chain(proxy::chain::Settings),
	}

	impl DetailsBuilder {
		/// Creates a [`Details`].
		///
		/// # Errors
		///
		/// Returns an error if the inner type failed to build.
		#[implement(map_arc_into)]
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

impl Default for DetailsBuilder {
	#[inline]
	fn default() -> Self {
		Self::Freedom(Default::default())
	}
}

// -------------------------------------------------
//                   Outbound
// -------------------------------------------------

pub struct Outbound {
	pub tag: Tag,
	settings: Details,
	pub transport: crate::transport::Outbound,
}

impl Outbound {
	pub(crate) async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		let transport = &self.transport;
		self.settings
			.connect_stream(
				Box::new(|addr: SocksAddr, context: &dyn ProxyContext| {
					async move { transport.connect(&addr, context).await }.boxed()
				}),
				dst.clone(),
				context,
			)
			.await
	}
}

#[cfg(feature = "use-udp")]
impl udp::GetConnector for Outbound {
	fn get_udp_connector(&self) -> Option<udp::Connector<'_>> {
		self.settings.get_udp_connector()
	}
}

impl GetProtocolName for Outbound {
	fn protocol_name(&self) -> &'static str {
		self.settings.protocol_name()
	}
}

#[async_trait]
impl Connector for Outbound {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		let transport = &self.transport;
		self.settings
			.connect_stream(
				Box::new(|addr: SocksAddr, context: &dyn ProxyContext| {
					async move { transport.connect(&addr, context).await }.boxed()
				}),
				dst.clone(),
				context,
			)
			.await
	}
}

#[async_trait]
impl StreamConnector for Outbound {
	async fn connect_stream<'a>(
		&'a self,
		stream_func: Box<StreamFunc<'a>>,
		dst: SocksAddr,
		context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		let transport = &self.transport;
		let stream_func = Box::new(move |addr: SocksAddr, context: &'a dyn ProxyContext| {
			async move {
				let stream = stream_func(addr.clone(), context).await?;
				transport.connect_stream(stream, &addr).await
			}
			.boxed()
		});
		self.settings
			.connect_stream(stream_func, dst, context)
			.await
	}
}

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Builder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tag: Tag,
	#[cfg_attr(feature = "use_serde", serde(flatten))]
	pub settings: DetailsBuilder,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: crate::transport::outbound::Builder,
}

impl Builder {
	/// Creates a [`Outbound`].
	///
	/// # Errors
	///
	/// Returns an error if `self.settings` failed to build.
	#[inline]
	pub fn build(self) -> Result<Outbound, BoxStdErr> {
		Ok(Outbound {
			tag: self.tag,
			settings: self.settings.build()?,
			transport: self.transport.build()?,
		})
	}

	/// Parse a URL into [`Builder`].
	///
	/// # Errors
	/// Return an error if
	/// - `url` scheme does not match any of the protocol names
	/// - `url` does not match the protocol's format
	/// - the protocol does not support URL parsing
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		use crate::{proxy, transport};
		type ParseFunc = Box<
			dyn Fn(
				&url::Url,
			) -> Result<
				(Option<Tag>, DetailsBuilder, transport::outbound::Builder),
				BoxStdErr,
			>,
		>;

		let tag: Tag = url.fragment().map(Into::into).unwrap_or_default();
		let mut parse_url_map = std::collections::HashMap::<&str, ParseFunc>::new();
		parse_url_map.insert(
			proxy::freedom::PROTOCOL_NAME,
			Box::new(|url| {
				proxy::freedom::Settings::parse_url(url)
					.map(|b| (None, b.into(), Default::default()))
			}),
		);
		#[cfg(feature = "socks5-outbound")]
		{
			use proxy::socks5::{outbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| {
					SettingsBuilder::parse_url(url).map(|b| (None, b.into(), Default::default()))
				}),
			);
		}
		#[cfg(feature = "http-outbound")]
		{
			use proxy::http::{outbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| {
					SettingsBuilder::parse_url(url).map(|b| (None, b.into(), Default::default()))
				}),
			);
		}
		#[cfg(any(
			feature = "shadowsocks-outbound-openssl",
			feature = "shadowsocks-outbound-ring"
		))]
		{
			use proxy::shadowsocks::{outbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| {
					SettingsBuilder::parse_url(url).map(|b| (None, b.into(), Default::default()))
				}),
			);
		}
		#[cfg(feature = "trojan-outbound")]
		{
			use proxy::trojan::{outbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| {
					SettingsBuilder::parse_url(url).map(|b| (None, b.into(), Default::default()))
				}),
			);
		}
		#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
		{
			use proxy::vmess::{outbound::SettingsBuilder, PROTOCOL_NAME};
			parse_url_map.insert(
				PROTOCOL_NAME,
				Box::new(|url| {
					SettingsBuilder::parse_url(url)
						.map(|(tag, b, transport)| (tag, b.into(), transport))
				}),
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
		let (new_tag, settings, transport) = parse_url(url)?;
		Ok(Builder {
			tag: new_tag.unwrap_or(tag),
			settings,
			transport,
		})
	}
}

impl crate::protocol::DisplayInfo for Builder {
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
