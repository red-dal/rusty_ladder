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

use super::BUFFER_CAPACITY;
use crate::{prelude::*, utils::poll_write_all};
use futures::ready;
use std::{
	io,
	pin::Pin,
	task::{Context, Poll},
};

pub trait Encode: Send + Sync + Unpin {
	fn encode_into(&mut self, src: &[u8], buf: &mut Vec<u8>) -> Result<(), BoxStdErr>;
}

impl<T: Encode> Encode for Box<T> {
	#[inline]
	fn encode_into(&mut self, src: &[u8], buf: &mut Vec<u8>) -> Result<(), BoxStdErr> {
		self.as_mut().encode_into(src, buf)
	}
}

#[derive(Debug, PartialEq, Eq)]
enum WriterState {
	/// Encoding bytes from source into buffer.
	Encoding,
	/// Consuming buffer and writing its bytes.
	///
	/// Contains a usize as the current start position of
	/// the buffer's remaining.
	Writing(usize),
	Closed,
}

/// A writer that encode bytes with a [`Encode`] and write them into another [`AsyncWrite`].
///
/// If you want to access the internal encoder or writer,
/// just use `w` and `encoder` field directly.
pub struct FrameWriter<E: Encode, W: AsyncWrite + Unpin> {
	buf: Vec<u8>,
	state: WriterState,
	pub max_payload_len: usize,
	pub encoder: E,
	pub w: W,
}

impl<E, W> FrameWriter<E, W>
where
	E: Encode,
	W: AsyncWrite + Unpin,
{
	/// Create a new [`FrameWriter`].
	///
	/// If bytes that you want to write is larger than `max_payload_len`,
	/// only `max_payload_len` bytes will be written.
	pub fn new(max_payload_len: usize, encoder: E, w: W) -> Self {
		let buf = Vec::with_capacity(BUFFER_CAPACITY);
		Self {
			buf,
			state: WriterState::Encoding,
			max_payload_len,
			encoder,
			w,
		}
	}
}

impl<E, W> AsyncWrite for FrameWriter<E, W>
where
	E: Encode,
	W: AsyncWrite + Unpin,
{
	/// If `src` is larger than `self.max_payload_len`,
	/// only `src[..max_payload_len]` will be written.
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		mut src: &[u8],
	) -> Poll<Result<usize, io::Error>> {
		// `src` will be encoded into `self.buf`
		// then written into `self.w`.

		// In order to implement AsyncWrite and be compatible with
		// other IO (chain proxy), a buffer must be used.

		// In theory you can make a new trait with function like
		//
		// poll_write_vec(self, src: &mut Vec<u8>);
		//
		// and make a wrapper with buffer that implements AsyncWrite,
		// so some copying can be avoided and less memory is used.
		//
		// But to do that a lot of codes needs to be rewritten
		// (like in the `relay` mod) and I am lazy.

		let me = self.get_mut();
		// Truncate extra bytes.
		if src.len() > me.max_payload_len {
			src = &src[..me.max_payload_len];
		}
		loop {
			match &mut me.state {
				WriterState::Encoding => {
					trace!("Encoding src ({} bytes) into buf", src.len());
					me.encoder
						.encode_into(src, &mut me.buf)
						.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

					// Next goes to Writing.
					me.state = WriterState::Writing(0);
				}
				WriterState::Writing(pos) => {
					ready!(poll_write_all(Pin::new(&mut me.w), cx, pos, &me.buf))?;
					trace!(
						"Done writing data from buf ({} bytes): {:?}",
						me.buf.len(),
						&me.buf[..16]
					);
					// Clear up buffer so encoder don't accidentally append bytes
					// into it instead of overwritten it.
					me.buf.clear();
					// Next goes back to Encoding.
					me.state = WriterState::Encoding;
					return Poll::Ready(Ok(src.len()));
				}
				WriterState::Closed => {
					return Err(io::Error::new(
						io::ErrorKind::BrokenPipe,
						"FrameWriter already closed.",
					))
					.into()
				}
			}
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let me = self.get_mut();
		Pin::new(&mut me.w).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		// Just call the inner writer's poll_shutdown.
		// Maybe add a custom encode_eof in Encode trait and write some bytes while shutting down.
		let me = self.get_mut();
		me.state = WriterState::Closed;
		Pin::new(&mut me.w).poll_shutdown(cx)
	}
}
