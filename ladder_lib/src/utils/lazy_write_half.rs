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

use super::poll_write_all;
use crate::prelude::*;
use futures::ready;
use std::{
	io,
	task::{Context, Poll},
};

#[derive(PartialEq, Eq)]
enum LazyState {
	Lazy,
	Buffering(usize),
	Done,
}

struct LazyWriteHelper {
	buf: Vec<u8>,
	state: LazyState,
	lazy: bool,
}

impl LazyWriteHelper {
	#[inline]
	pub fn new(buf: Vec<u8>) -> Self {
		Self {
			buf,
			state: LazyState::Lazy,
			lazy: true,
		}
	}

	#[inline]
	#[allow(dead_code)]
	pub fn stop_being_lazy(&mut self) {
		debug_assert!(self.state == LazyState::Lazy);
		self.lazy = false;
		if self.buf.is_empty() {
			self.state = LazyState::Done;
		}
	}

	pub fn poll_write<W>(
		&mut self,
		writer: &mut W,
		cx: &mut Context<'_>,
		src: &[u8],
	) -> Poll<Result<usize, io::Error>>
	where
		W: AsyncWrite + Unpin,
	{
		loop {
			match &mut self.state {
				LazyState::Lazy => {
					self.buf.put(src);
					if self.lazy {
						return Ok(src.len()).into();
					}
					self.state = LazyState::Buffering(0);
				}
				LazyState::Buffering(pos) => {
					if !self.buf.is_empty() {
						ready!(poll_write_all(Pin::new(writer), cx, pos, &self.buf))?;
					}
					self.buf = Vec::new();
					self.state = LazyState::Done;
					return Ok(src.len()).into();
				}
				LazyState::Done => return Pin::new(writer).poll_write(cx, src),
			}
		}
	}

	pub fn poll_flush<W>(&mut self, writer: &mut W, cx: &mut Context) -> Poll<io::Result<()>>
	where
		W: AsyncWrite + Unpin,
	{
		loop {
			match &mut self.state {
				LazyState::Lazy => {
					if self.buf.is_empty() {
						self.state = LazyState::Done;
					} else {
						self.state = LazyState::Buffering(0);
					}
				}
				LazyState::Buffering(pos) => {
					ready!(poll_write_all(Pin::new(writer), cx, pos, &self.buf))?;
					self.buf = Vec::new();
					self.state = LazyState::Done;
				}
				LazyState::Done => return Pin::new(writer).poll_flush(cx),
			}
		}
	}
}

impl Default for LazyWriteHelper {
	#[inline]
	fn default() -> Self {
		Self::new(Vec::new())
	}
}

pub struct LazyWriteHalf<W: AsyncWrite + Unpin> {
	inner: W,
	writer: LazyWriteHelper,
	done_flushing: bool,
}

#[allow(dead_code)]
impl<W: AsyncWrite + Unpin> LazyWriteHalf<W> {
	#[inline]
	pub fn new(w: W, data: Vec<u8>) -> Self {
		let mut res = Self {
			inner: w,
			writer: LazyWriteHelper::new(data),
			done_flushing: false,
		};
		res.stop_being_lazy();
		res
	}

	pub fn new_not_lazy(w: W, data: Vec<u8>) -> Self {
		let mut res = Self::new(w, data);
		res.stop_being_lazy();
		res
	}

	#[inline]
	pub fn stop_being_lazy(&mut self) {
		self.writer.stop_being_lazy();
	}

	#[inline]
	#[allow(dead_code)]
	pub fn inner(self) -> W {
		self.inner
	}
}

impl<W: AsyncWrite + Unpin> AsyncWrite for LazyWriteHalf<W> {
	#[inline]
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		src: &[u8],
	) -> Poll<Result<usize, io::Error>> {
		let me = self.get_mut();
		me.writer.poll_write(&mut me.inner, cx, src)
	}

	#[inline]
	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let me = self.get_mut();
		me.writer.poll_flush(&mut me.inner, cx)
	}

	#[inline]
	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let me = self.get_mut();
		loop {
			if me.done_flushing {
				return Pin::new(&mut me.inner).poll_shutdown(cx);
			}
			ready!(me.writer.poll_flush(&mut me.inner, cx))?;
			me.done_flushing = true;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Cursor;
	use tokio::runtime::Runtime;

	#[test]
	fn test_lazy_buf_writer() {
		// init writer
		let cursor = Cursor::new(Vec::<u8>::with_capacity(4096));

		let rt = Runtime::new().unwrap();
		rt.block_on(async {
			// write something
			let mut data: Vec<u8> = Vec::with_capacity(4096);
			data.extend_from_slice(b"Hello world. This is some data.");

			let mut writer = LazyWriteHalf::new(cursor, data.clone());
			writer.stop_being_lazy();
			writer.write(b"This is some other data.").await.unwrap();

			let result = writer.inner.into_inner();

			assert_eq!(&result[..data.len()], &data[..]);
			assert_eq!(&result[data.len()..], b"This is some other data.");
		});
	}
}
