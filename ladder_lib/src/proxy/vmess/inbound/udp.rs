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
	prelude::SocksAddr,
	protocol::inbound::{Session, UdpProxyStream, UdpRecv, UdpResult, UdpSend},
};

use super::{super::MAX_PAYLOAD_LENGTH, tcp};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct ReadHalf<R: AsyncRead + Unpin> {
	dst: SocksAddr,
	inner: tcp::ReadHalf<R>,
	buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> ReadHalf<R> {
	pub fn new(inner: tcp::ReadHalf<R>, dst: SocksAddr) -> Self {
		Self {
			dst,
			inner,
			buf: vec![0_u8; MAX_PAYLOAD_LENGTH],
		}
	}
}

pub struct WriteHalf<W: AsyncWrite + Unpin> {
	inner: tcp::WriteHalf<W>,
}

impl<W: AsyncWrite + Unpin> WriteHalf<W> {
	pub fn new(inner: tcp::WriteHalf<W>) -> Self {
		Self { inner }
	}
}

pub fn new_stream<R, W>(
	read_half: tcp::ReadHalf<R>,
	write_half: tcp::WriteHalf<W>,
	dst: SocksAddr,
) -> UdpProxyStream
where
	R: 'static + AsyncRead + Unpin + Send + Sync,
	W: 'static + AsyncWrite + Unpin + Send + Sync,
{
	let read_half = ReadHalf::new(read_half, dst);
	let write_half = WriteHalf::new(write_half);
	UdpProxyStream {
		read_half: Box::new(read_half),
		write_half: Box::new(write_half),
	}
}

#[async_trait]
impl<R: AsyncRead + Send + Sync + Unpin> UdpRecv for ReadHalf<R> {
	async fn recv_inbound(&mut self, buf: &mut [u8]) -> std::io::Result<UdpResult> {
		self.buf.resize(MAX_PAYLOAD_LENGTH, 0);
		let len = self.inner.read(&mut self.buf).await?;
		let len = std::cmp::min(len, buf.len());
		buf[..len].copy_from_slice(&self.buf[..len]);
		Ok(UdpResult {
			len,
			src: None,
			dst: self.dst.clone(),
		})
	}
}

#[async_trait]
impl<W: AsyncWrite + Send + Sync + Unpin> UdpSend for WriteHalf<W> {
	async fn send_inbound(&mut self, _sess: &Session, buf: &[u8]) -> std::io::Result<usize> {
		let len = std::cmp::min(buf.len(), MAX_PAYLOAD_LENGTH);
		let payload = &buf[..len];
		self.inner.write(payload).await
	}
}
