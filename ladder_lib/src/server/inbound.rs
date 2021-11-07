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
		inbound::{AcceptError, AcceptResult, TcpAcceptor},
		BytesStream, GetProtocolName, Network,
	},
	utils::OneOrMany,
};
use async_trait::async_trait;

macro_rules! make_inbound {
	{
		$(#[$attrs:meta])*
		$($header:ident)* ($($enum_name:ident)?) {
			Tunnel($($tunnel_item:tt)+) $(=> $tunnel_body:block)?,
			Socks5($($socks5_item:tt)+) $(=> $socks5_body:block)?,
			Http($($http_item:tt)+) $(=> $http_body:block)?,
			Shadowsocks($($ss_item:tt)+) $(=> $ss_body:block)?,
			Vmess($($vmess_item:tt)+) $(=> $vmess_body:block)?,
		}
	} => {
		$(#[$attrs])*
		$($header)* {
			$($enum_name::)? Tunnel($($tunnel_item)+) $(=> $tunnel_body)?,
			#[cfg(feature = "socks5-inbound")]
			$($enum_name::)? Socks5($($socks5_item)+) $(=> $socks5_body)?,
			#[cfg(feature = "http-inbound")]
			$($enum_name::)? Http($($http_item)+) $(=> $http_body)?,
			#[cfg(any(
				feature = "shadowsocks-inbound-openssl",
				feature = "shadowsocks-inbound-ring"
			))]
			$($enum_name::)? Shadowsocks($($ss_item)+) $(=> $ss_body)?,
			#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
			$($enum_name::)? Vmess($($vmess_item)+) $(=> $vmess_body)?,
		}
	};
}

macro_rules! match_inbound {
	{$item:ident, $enum_name:ident,
		Tunnel($tunnel_item:ident) => $tunnel_body:block,
		Socks5($socks5_item:ident) => $socks5_body:block,
		Http($http_item:ident) => $http_body:block,
		Shadowsocks($ss_item:ident) => $ss_body:block,
		Vmess($vmess_item:ident) => $vmess_body:block,
	} => {
		make_inbound! {
			match $item ($enum_name) {
				Tunnel($tunnel_item) => $tunnel_body,
				Socks5($socks5_item) => $socks5_body,
				Http($http_item) => $http_body,
				Shadowsocks($ss_item) => $ss_body,
				Vmess($vmess_item) => $vmess_body,
			}
		}
	};
}

macro_rules! dispatch_inbound {
	($item:ident, $enum_name:ident, $with:ident, $body:block) => {
		match_inbound! {$item, $enum_name,
			Tunnel($with) => $body,
			Socks5($with) => $body,
			Http($with) => $body,
			Shadowsocks($with) => $body,
			Vmess($with) => $body,
		}
	};
}

make_inbound! {
	pub enum Details () {
		Tunnel(tunnel::Settings),
		Socks5(socks5::inbound::Settings),
		Http(http::inbound::Settings),
		Shadowsocks(shadowsocks::inbound::Settings),
		Vmess(vmess::inbound::Settings),
	}
}

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

impl GetProtocolName for Details {
	fn protocol_name(&self) -> &'static str {
		dispatch_inbound!(self, Self, s, { s.protocol_name() })
	}

	fn network(&self) -> Network {
		dispatch_inbound!(self, Self, s, { s.network() })
	}
}

#[async_trait]
impl TcpAcceptor for Details {
	async fn accept_tcp<'a>(
		&'a self,
		stream: BytesStream,
	) -> Result<AcceptResult<'a>, AcceptError> {
		dispatch_inbound!(self, Self, s, { s.accept_tcp(stream).await })
	}
}

make_inbound! {
	#[derive(Debug)]
	#[cfg_attr(
		feature = "use_serde",
		derive(serde::Deserialize),
		serde(rename_all = "lowercase", tag = "protocol")
	)]
	pub enum DetailsBuilder () {
		Tunnel(tunnel::Settings),
		Socks5(socks5::inbound::SettingsBuilder),
		Http(http::inbound::SettingsBuilder),
		Shadowsocks(shadowsocks::inbound::SettingsBuilder),
		Vmess(vmess::inbound::SettingsBuilder),
	}
}

impl DetailsBuilder {
	#[inline]
	#[allow(clippy::missing_errors_doc)]
	pub fn build(self) -> Result<Details, BoxStdErr> {
		Ok(match_inbound! {self, Self,
			Tunnel(s) => { Details::Tunnel(s) },
			Socks5(s) => { Details::Socks5(s.build()?) },
			Http(s) => { Details::Http(s.build()?) },
			Shadowsocks(s) => { Details::Shadowsocks(s.build()?) },
			Vmess(s) => { Details::Vmess(s.build()?) },
		})
	}
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub enum ErrorHandlingPolicy {
	#[cfg_attr(feature = "use_serde", serde(rename = "drop"))]
	Drop,
	#[cfg_attr(feature = "use_serde", serde(rename = "unlimited_timeout"))]
	UnlimitedTimeout,
}

impl Default for ErrorHandlingPolicy {
	fn default() -> Self {
		Self::Drop
	}
}

pub struct Inbound {
	pub tag: Tag,
	pub addr: OneOrMany<SocketAddr>,
	pub settings: Details,
	pub err_policy: ErrorHandlingPolicy,
}

impl Inbound {
	#[inline]
	#[must_use]
	pub fn protocol_name(&self) -> &'static str {
		self.settings.protocol_name()
	}
}

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Builder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tag: Tag,
	pub addr: OneOrMany<SocketAddr>,
	#[cfg_attr(feature = "use_serde", serde(flatten))]
	pub settings: DetailsBuilder,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub err_policy: ErrorHandlingPolicy,
}

impl Builder {
	/// Creates a [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if `self.settings` failed to build.
	#[inline]
	pub fn build(self) -> Result<Inbound, BoxStdErr> {
		Ok(Inbound {
			tag: self.tag,
			addr: self.addr,
			settings: self.settings.build()?,
			err_policy: self.err_policy,
		})
	}
}
