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
	super::MAX_PAYLOAD_LENGTH,
	tcp,
};
use crate::{
	prelude::*,
	protocol::outbound::tunnel::{UdpProxyStream, UdpRecv, UdpSend},
	utils::codec::{self, FrameWriter},
};

pub fn new_udp_stream<R, W, E, D>(
	read_half: tcp::ReadHalf<R, D>,
	write_half: FrameWriter<E, W>,
) -> UdpProxyStream
where
	R: 'static + AsyncRead + Unpin + Send + Sync,
	W: 'static + AsyncWrite + Unpin + Send + Sync,
	D: 'static + codec::Decode + Sync,
	E: 'static + codec::Encode + Sync,
{
	let read_half = ReadHalf::new(read_half);
	let write_half = WriteHalf::new(write_half);
	UdpProxyStream {
		read_half: Box::new(read_half),
		write_half: Box::new(write_half),
	}
}

struct ReadHalf<R, D>
where
	R: AsyncRead + Unpin,
	D: 'static + codec::Decode,
{
	reader: tcp::ReadHalf<R, D>,
	tmp_buf: Vec<u8>,
}

impl<R, D> ReadHalf<R, D>
where
	R: AsyncRead + Unpin,
	D: codec::Decode,
{
	fn new(reader: tcp::ReadHalf<R, D>) -> Self {
		Self {
			reader,
			tmp_buf: vec![0_u8; MAX_PAYLOAD_LENGTH],
		}
	}
}

#[async_trait]
impl<R, D> UdpRecv for ReadHalf<R, D>
where
	R: AsyncRead + Unpin + Send + Sync,
	D: codec::Decode,
{
	async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		let len = self.reader.read(&mut self.tmp_buf).await?;
		let tmp_buf = &self.tmp_buf[..len];

		let len = std::cmp::min(buf.len(), tmp_buf.len());

		buf[..len].copy_from_slice(&tmp_buf[..len]);

		return Ok(len);
	}
}

struct WriteHalf<W, E>
where
	W: AsyncWrite + Unpin,
	E: 'static + codec::Encode,
{
	writer: FrameWriter<E, W>,
}

impl<W, E> WriteHalf<W, E>
where
	W: AsyncWrite + Unpin,
	E: codec::Encode,
{
	fn new(writer: FrameWriter<E, W>) -> Self {
		Self { writer }
	}
}

#[async_trait]
impl<W, E> UdpSend for WriteHalf<W, E>
where
	W: AsyncWrite + Unpin + Send + Sync,
	E: codec::Encode,
{
	async fn send(&mut self, payload: &[u8]) -> std::io::Result<usize> {
		self.writer.write_all(payload).await?;
		return Ok(payload.len());
	}

	async fn shutdown(&mut self) -> std::io::Result<()> {
		return self.writer.shutdown().await;
	}
}
