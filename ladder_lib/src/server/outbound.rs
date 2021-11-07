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

#[allow(clippy::wildcard_imports)]
use crate::proxy::*;
use crate::{
	prelude::*,
	protocol::{
		GetConnector, GetProtocolName, OutboundError, ProxyContext, ProxyStream, TcpConnector,
		TcpStreamConnector, UdpConnector,
	},
};

macro_rules! make_outbound {
	{
		$(#[$attrs:meta])*
		$($header:ident)* ($($enum_name:ident)?) {
			Freedom($($tunnel_item:tt)+) $(=> $tunnel_body:block)?,
			Socks5($($socks5_item:tt)+) $(=> $socks5_body:block)?,
			Http($($http_item:tt)+) $(=> $http_body:block)?,
			Shadowsocks($($ss_item:tt)+) $(=> $ss_body:block)?,
			Trojan($($trojan_item:tt)+) $(=> $trojan_body:block)?,
			Vmess($($vmess_item:tt)+) $(=> $vmess_body:block)?,
			Chain($($chain_item:tt)+) $(=> $chain_body:block)?,
		}
	} => {
		$(#[$attrs])*
		$($header)* {
			$($enum_name::)? Freedom($($tunnel_item)+) $(=> $tunnel_body)?,
			#[cfg(feature = "socks5-outbound")]
			$($enum_name::)? Socks5($($socks5_item)+) $(=> $socks5_body)?,
			#[cfg(feature = "http-outbound")]
			$($enum_name::)? Http($($http_item)+) $(=> $http_body)?,
			#[cfg(any(
				feature = "shadowsocks-outbound-openssl",
				feature = "shadowsocks-outbound-ring"
			))]
			$($enum_name::)? Shadowsocks($($ss_item)+) $(=> $ss_body)?,
			#[cfg(feature = "trojan-outbound")]
			$($enum_name::)? Trojan($($trojan_item)+) $(=> $trojan_body)?,
			#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
			$($enum_name::)? Vmess($($vmess_item)+) $(=> $vmess_body)?,
			#[cfg(feature = "chain-outbound")]
			$($enum_name::)? Chain($($chain_item)+) $(=> $chain_body)?,
		}
	};
}

make_outbound! {
	pub enum Details () {
		Freedom(Arc<freedom::Settings>),
		Socks5(Arc<socks5::outbound::Settings>),
		Http(Arc<http::outbound::Settings>),
		Shadowsocks(Arc<shadowsocks::outbound::Settings>),
		Trojan(Arc<trojan::Settings>),
		Vmess(Arc<vmess::outbound::Settings>),
		Chain(Arc<chain::Settings>),
	}
}

macro_rules! match_outbound {
	{$obj:ident, $enum_name:ident,
		Freedom($freedom_item:ident) => $freedom_body:expr,
		Socks5($socks5_item:ident) => $socks5_body:expr,
		Http($http_item:ident) => $http_body:expr,
		Shadowsocks($ss_item:ident) => $ss_body:expr,
		Trojan($trojan_item:ident) => $trojan_body:expr,
		Vmess($vmess_item:ident) => $vmess_body:expr,
		Chain($chain_item:ident) => $chain_body:expr,
	} => {
		make_outbound! {
			match $obj ($enum_name) {
				Freedom($freedom_item) => {$freedom_body},
				Socks5($socks5_item) => {$socks5_body},
				Http($http_item) => {$http_body},
				Shadowsocks($ss_item) => {$ss_body},
				Trojan($trojan_item) => {$trojan_body},
				Vmess($vmess_item) => {$vmess_body},
				Chain($chain_item) => {$chain_body},
			}
		}
	};
}

macro_rules! dispatch_outbound {
	($obj:ident, $enum_name:ident, $with:ident, $body:block) => {
		match_outbound! { $obj, $enum_name,
			Freedom($with) => $body,
			Socks5($with) => $body,
			Http($with) => $body,
			Shadowsocks($with) => $body,
			Trojan($with) => $body,
			Vmess($with) => $body,
			Chain($with) => $body,
		}
	};
}

impl Details {
	#[must_use]
	pub fn get_tcp_connector(&self) -> Arc<dyn TcpConnector> {
		dispatch_outbound!(self, Self, s, { s.clone() })
	}

	#[allow(clippy::match_same_arms)]
	#[must_use]
	pub fn get_tcp_stream_connector(&self) -> Option<Arc<dyn TcpStreamConnector>> {
		match_outbound! {self, Self,
			Freedom(_s) => None,
			Socks5(s) => Some(s.clone()),
			Http(s) => Some(s.clone()),
			Shadowsocks(s) => Some(s.clone()),
			Trojan(s) => Some(s.clone()),
			Vmess(s) => Some(s.clone()),
			Chain(_s) => None,
		}
	}
}

impl GetProtocolName for Details {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		return dispatch_outbound!(self, Self, s, { s.protocol_name() });
	}
}

#[async_trait]
impl TcpConnector for Details {
	#[inline]
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<ProxyStream, OutboundError> {
		return dispatch_outbound!(self, Self, s, { s.connect(dst, context).await });
	}
}

impl GetConnector for Details {
	fn get_udp_connector(&self) -> Option<UdpConnector<'_>> {
		#[cfg(feature = "use-udp")]
		return dispatch_outbound!(self, Self, s, { s.get_udp_connector() });
		#[cfg(not(feature = "use-udp"))]
		None
	}
}

make_outbound! {
	#[derive(Debug)]
	#[cfg_attr(
		feature = "use_serde",
		derive(serde::Deserialize),
		serde(tag = "protocol", rename_all = "lowercase")
	)]
	pub enum DetailsBuilder () {
		Freedom(freedom::Settings),
		Socks5(socks5::outbound::SettingsBuilder),
		Http(http::outbound::SettingsBuilder),
		Shadowsocks(shadowsocks::outbound::SettingsBuilder),
		Trojan(trojan::SettingsBuilder),
		Vmess(vmess::outbound::SettingsBuilder),
		Chain(chain::Settings),
	}
}

impl DetailsBuilder {
	#[inline]
	#[allow(clippy::missing_errors_doc)]
	pub fn build(self) -> Result<Details, BoxStdErr> {
		Ok(match_outbound! { self, Self,
			Freedom(b) => Details::Freedom(Arc::new(b)),
			Socks5(b) => Details::Socks5(Arc::new(b.build()?)),
			Http(b) => Details::Http(Arc::new(b.build()?)),
			Shadowsocks(b) => Details::Shadowsocks(Arc::new(b.build()?)),
			Trojan(b) => Details::Trojan(Arc::new(b.build()?)),
			Vmess(b) => Details::Vmess(Arc::new(b.build()?)),
			Chain(b) => Details::Chain(Arc::new(b)),
		})
	}
}

pub struct Outbound {
	pub tag: Tag,
	pub settings: Details,
}

impl Outbound {}

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Builder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tag: Tag,
	#[cfg_attr(feature = "use_serde", serde(flatten))]
	pub settings: DetailsBuilder,
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
		})
	}
}
