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

use super::{
	stat::{Id, RegisterArgs, SessionHandle},
	Error,
};
use crate::{
	network,
	prelude::*,
	protocol::{AsyncReadWrite, GetProtocolName},
	utils::OneOrMany,
	Monitor,
};
use std::{future::Future, time::SystemTime};

#[ladder_lib_macro::impl_variants(Details)]
mod details {
	use crate::{
		protocol::{
			inbound::{AcceptError, AcceptResult, SessionInfo, TcpAcceptor},
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
			info: SessionInfo,
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
	pub settings: Details,
	pub network: network::Config,
	pub err_policy: ErrorHandlingPolicy,
}

impl Inbound {
	#[inline]
	#[must_use]
	pub fn protocol_name(&self) -> &'static str {
		self.settings.protocol_name()
	}

	/// Accept and handle byte stream request forever.
	///
	/// # Errors
	///
	/// Returns an [`Error`] if there are any invalid configurations or IO errors.
	///
	/// Errors occurred in `callback` will not return an [`Error`].
	pub async fn serve(
		self: &Arc<Self>,
		inbound_ind: usize,
		monitor: Option<Monitor>,
		callback: impl 'static + Callback,
	) -> Result<(), Error> {
		let callback = Arc::new(callback);
		let mut acceptor = self.network.bind().await?;
		loop {
			let callback = callback.clone();
			let ar = acceptor.accept().await?;
			let monitor = monitor.clone();
			// randomly generated connection ID
			let conn_id = rand::thread_rng().next_u64();
			let inbound = self.clone();
			tokio::spawn(async move {
				let stream = ar.stream;
				let from = ar.addr.get_peer();
				let stat_handle = monitor.as_ref().map(|m| {
					m.register_tcp_session(RegisterArgs {
						conn_id,
						inbound_ind,
						inbound_tag: inbound.tag.clone(),
						start_time: SystemTime::now(),
						from,
					})
				});
				if let Err(e) = callback
					.run(stat_handle.clone(), stream, ar.addr, conn_id)
					.await
				{
					error!(
						"Error occurred when serving {} inbound '{}': {} ",
						inbound.protocol_name(),
						inbound.tag,
						e
					);
				}
				// kill connection in the monitor
				let end_time = SystemTime::now();
				if let Some(stat_handle) = stat_handle {
					stat_handle.set_dead(end_time);
				}
			});
		}
	}
}

pub trait Callback: Send + Sync {
	type Fut: Future<Output = Result<(), Error>> + Send;

	fn run(
		&self,
		sh: Option<SessionHandle>,
		stream: Box<dyn AsyncReadWrite>,
		addr: network::Addrs,
		conn_id: Id,
	) -> Self::Fut;
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

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Builder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tag: Tag,
	pub addr: OneOrMany<smol_str::SmolStr>,
	#[cfg_attr(feature = "use_serde", serde(flatten))]
	pub settings: DetailsBuilder,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub err_policy: ErrorHandlingPolicy,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub network_type: NetworkType,
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
		})
	}
}
