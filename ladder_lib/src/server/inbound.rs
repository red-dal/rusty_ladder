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

use crate::{prelude::*, protocol::GetProtocolName, utils::OneOrMany};

#[ladder_lib_macro::impl_variants(Details)]
mod details {
	use crate::{
		protocol::{
			inbound::{AcceptError, AcceptResult, StreamInfo, TcpAcceptor},
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
	}

	impl GetProtocolName for Details {
		#[implement]
		fn protocol_name(&self) -> &'static str {}
		#[implement]
		fn network(&self) -> Network {}
	}

	#[async_trait]
	impl TcpAcceptor for Details {
		#[implement]
		async fn accept_tcp<'a>(
			&'a self,
			stream: Box<dyn AsyncReadWrite>,
			info: Option<StreamInfo>,
		) -> Result<AcceptResult<'a>, AcceptError> {
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
}
pub use details_builder::DetailsBuilder;

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