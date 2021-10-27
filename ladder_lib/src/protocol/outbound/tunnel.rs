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

use crate::prelude::*;
use std::io;
use tokio::net::{ToSocketAddrs, UdpSocket};

#[async_trait]
pub trait UdpRecv: Unpin + Send + Sync {
	async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait UdpSend: Unpin + Send + Sync {
	async fn send(&mut self, payload: &[u8]) -> io::Result<usize>;
	async fn shutdown(&mut self) -> io::Result<()>;
}

pub struct UdpProxyStream {
	pub read_half: Box<dyn UdpRecv>,
	pub write_half: Box<dyn UdpSend>,
}

#[async_trait]
impl UdpRecv for UdpProxyStream {
	#[inline]
	async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		return self.read_half.recv(buf).await;
	}
}

#[async_trait]
impl UdpSend for UdpProxyStream {
	#[inline]
	async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
		return self.write_half.send(buf).await;
	}

	async fn shutdown(&mut self) -> io::Result<()> {
		return self.write_half.shutdown().await;
	}
}

#[derive(Clone)]
pub struct UdpSocketWrapper(pub Arc<UdpSocket>);

impl UdpSocketWrapper {
	/// Wrapper for [`UdpSocket::bind`].
	#[allow(clippy::missing_errors_doc)]
	pub async fn connect(addr: impl ToSocketAddrs) -> io::Result<Self> {
		let socket = UdpSocket::bind(SocketAddr::new([0, 0, 0, 0].into(), 0)).await?;
		socket.connect(addr).await?;

		Ok(UdpSocketWrapper(Arc::new(socket)))
	}
}

#[async_trait]
impl UdpRecv for UdpSocketWrapper {
	async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		self.0.recv(buf).await
	}
}

#[async_trait]
impl UdpSend for UdpSocketWrapper {
	async fn send(&mut self, payload: &[u8]) -> io::Result<usize> {
		self.0.send(payload).await
	}

	async fn shutdown(&mut self) -> io::Result<()> {
		// Do nothing
		Ok(())
	}
}
