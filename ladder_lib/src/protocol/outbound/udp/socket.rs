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

use tokio::net::{ToSocketAddrs, UdpSocket};

use crate::prelude::*;
use std::io;

#[async_trait]
pub trait RecvPacket: Unpin + Send + Sync {
	async fn recv_src(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)>;
}

#[async_trait]
pub trait SendPacket: Unpin + Send + Sync {
	async fn send_dst(&mut self, dst: &SocksAddr, buf: &[u8]) -> io::Result<usize>;
	async fn shutdown(&mut self) -> io::Result<()>;
}

pub struct PacketStream {
	pub read_half: Box<dyn RecvPacket>,
	pub write_half: Box<dyn SendPacket>,
}

#[async_trait]
impl RecvPacket for PacketStream {
	#[inline]
	async fn recv_src(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
		return self.read_half.recv_src(buf).await;
	}
}

#[async_trait]
impl SendPacket for PacketStream {
	#[inline]
	async fn send_dst(&mut self, dst: &SocksAddr, buf: &[u8]) -> io::Result<usize> {
		return self.write_half.send_dst(dst, buf).await;
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
	pub async fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
		let sock = UdpSocket::bind(addr).await?;
		trace!("UdpSocket binding on {}", sock.local_addr()?);
		Ok(Self(Arc::new(sock)))
	}
}

#[async_trait]
impl RecvPacket for UdpSocketWrapper {
	async fn recv_src(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
		let (len, remote) = self.0.recv_from(buf).await?;
		trace!(
			"UdpSocket on {} received packet from remote server {}",
			self.0.local_addr()?,
			remote
		);
		return Ok((len, remote.into()));
	}
}

#[async_trait]
impl SendPacket for UdpSocketWrapper {
	async fn send_dst(&mut self, dst: &SocksAddr, buf: &[u8]) -> io::Result<usize> {
		trace!(
			"UdpSocket on {} sending packet to remote server {}",
			self.0.local_addr()?,
			dst
		);
		let len = match &dst.dest {
			SocksDestination::Name(name) => self.0.send_to(buf, (name.as_str(), dst.port)).await?,
			SocksDestination::Ip(ip) => self.0.send_to(buf, (*ip, dst.port)).await?,
		};
		return Ok(len);
	}

	async fn shutdown(&mut self) -> io::Result<()> {
		Ok(())
	}
}
