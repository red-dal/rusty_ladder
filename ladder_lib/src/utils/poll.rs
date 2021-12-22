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
use futures::ready;
use std::{
	io,
	pin::Pin,
	task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

/// Poll read exactly `dst.len()` bytes into dst.
/// 
/// Returns `Err(UnexpectedEof)` if an eof is reached when there are some 
/// bytes read into the buffer but the buffer is not full.
/// 
/// Returns 'Ok(n)' otherwise, where `n` is `dst.len()` when the buffer is full,
/// and `n` is 0 where an eof is reached but buffer is still empty.
#[allow(dead_code)]
pub fn poll_read_exact<R>(
	mut reader: Pin<&mut R>,
	cx: &mut Context<'_>,
	buf: &mut [u8],
	pos: &mut usize,
) -> Poll<io::Result<usize>>
where
	R: AsyncRead,
{
	let buf_len = buf.len();
	while *pos < buf.len() {
		let mut buf = ReadBuf::new(&mut buf[*pos..]);
		ready!(reader.as_mut().poll_read(cx, &mut buf))?;

		let n = buf.filled().len();
		if n == 0 {
			if *pos == 0 {
				return Poll::Ready(Ok(0));
			} else if *pos == buf.capacity() {
				return Poll::Ready(Ok(buf_len));
			}
			return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
		}

		// Remember to set the len of the buffer.
		*pos += n;
	}
	Poll::Ready(Ok(buf.len()))
}

#[allow(dead_code)]
pub fn poll_write_all<W>(
	mut writer: Pin<&mut W>,
	cx: &mut Context<'_>,
	pos: &mut usize,
	src: &[u8],
) -> Poll<io::Result<()>>
where
	W: AsyncWrite + Unpin,
{
	debug_assert!(*pos <= src.len());
	// While there are still bytes left in buffer.
	while *pos < src.len() {
		let n = ready!(writer.as_mut().poll_write(cx, &src[*pos..]))?;
		if n == 0 {
			return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
		}
		// Advance position.
		let next_pos = *pos + n;
		*pos = next_pos;
	}
	Poll::Ready(Ok(()))
}
