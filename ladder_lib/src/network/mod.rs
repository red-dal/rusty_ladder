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

use crate::protocol::AsyncReadWrite;
use futures::{stream::SelectAll, StreamExt};
use std::{io, net::SocketAddr, pin::Pin, task::Poll};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
pub struct Addrs {
	pub peer: SocketAddr,
	pub local: SocketAddr,
}

impl Addrs {
	#[must_use]
	pub fn get_peer(&self) -> SocketAddr {
		self.peer
	}
}

#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct NetConfig {
	pub addr: Vec<SocketAddr>,
}

impl NetConfig {
	/// Create a [`TcpAcceptor`].
	///
	/// # Errors
	///
	/// Return a [`std::io::Error`] if TCP listener cannot be created
	/// on any of the addresses.
	pub async fn bind(&self) -> io::Result<TcpAcceptor> {
		let mut combined_streams = SelectAll::new();
		for a in self.addr.as_slice() {
			log::warn!("Listening TCP on {}", a);
			let listener = TcpListener::bind(a).await.map_err(|e| {
				io::Error::new(
					e.kind(),
					format!("cannot create TCP listener on {} ({})", a, e),
				)
			})?;
			let wrapper = TcpListenerStreamWrapper(listener);
			combined_streams.push(wrapper);
		}
		Ok(TcpAcceptor(combined_streams))
	}

	#[cfg(feature = "use-udp")]
	/// Create a list of [`tokio::net::UdpSocket`].
	///
	/// # Errors
	///
	/// Return [`std::io::Error`] if UDP socket cannot be created on
	/// any of the addresses.
	pub async fn bind_datagram(&self) -> io::Result<Vec<tokio::net::UdpSocket>> {
		let mut result = Vec::new();
		for addr in self.addr.as_slice() {
			let socket = tokio::net::UdpSocket::bind(addr).await?;
			result.push(socket);
		}
		Ok(result)
	}
}

impl std::fmt::Display for NetConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "TCP {{ ")?;
		let mut first = true;
		for a in &self.addr {
			if first {
				first = false;
			} else {
				write!(f, ", ")?;
			}
			write!(f, "{}", a)?;
		}
		write!(f, " }}")
	}
}

struct TcpListenerStreamWrapper(TcpListener);

impl futures::Stream for TcpListenerStreamWrapper {
	type Item = io::Result<(TcpStream, SocketAddr)>;

	#[inline]
	fn poll_next(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Option<Self::Item>> {
		self.get_mut().0.poll_accept(cx).map(Some)
	}
}

pub struct TcpAcceptor(SelectAll<TcpListenerStreamWrapper>);

impl TcpAcceptor {
	#[allow(clippy::missing_errors_doc)]
	pub async fn accept(&mut self) -> io::Result<AcceptResult> {
		let (stream, peer_addr) = self.0.next().await.ok_or_else(|| {
			io::Error::new(io::ErrorKind::InvalidData, "TcpListener run out of streams")
		})??;
		let local_addr = stream.local_addr()?;
		Ok(AcceptResult {
			stream: Box::new(stream),
			addr: Addrs {
				peer: peer_addr,
				local: local_addr,
			},
		})
	}
}

#[ladder_lib_macro::impl_variants(Config)]
mod config {
	use super::{Acceptor, NetConfig};
	use std::io;

	#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
	#[cfg_attr(feature = "use_serde", serde(rename_all = "lowercase", tag = "type"))]
	pub enum Config {
		Net(NetConfig),
	}

	impl Config {
		#[allow(clippy::missing_errors_doc)]
		#[implement(map_into)]
		pub async fn bind(&self) -> io::Result<Acceptor> {}
	}

	impl std::fmt::Display for Config {
		#[implement(map_into)]
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {}
	}
}
pub use config::Config;

pub struct AcceptResult {
	pub stream: Box<dyn AsyncReadWrite>,
	pub addr: Addrs,
}

#[ladder_lib_macro::impl_variants(Acceptor)]
mod acceptor {
	use super::{AcceptResult, TcpAcceptor};
	use std::io;

	pub enum Acceptor {
		Tcp(TcpAcceptor),
	}

	impl Acceptor {
		#[allow(clippy::missing_errors_doc)]
		#[implement]
		pub async fn accept(&mut self) -> io::Result<AcceptResult> {}
	}
}
pub use acceptor::Acceptor;

impl Acceptor {
	pub fn is_plain(&self) -> bool {
		matches!(self, Self::Tcp(_))
	}
}
