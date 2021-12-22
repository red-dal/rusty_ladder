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

enum State {
	BuildingBuffer,
	WritingFromBuffer(usize),
	WritingDirectly,
}

#[allow(dead_code)]
pub struct LazyWriteHalf<W: AsyncWrite + Unpin> {
	pub inner: W,
	state: State,
	buf: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> LazyWriteHalf<W> {
	pub fn new(w: W, data: Vec<u8>) -> Self {
		let (state, buf) = if data.is_empty() {
			(State::WritingDirectly, Vec::new())
		} else {
			(State::BuildingBuffer, data)
		};
		Self {
			inner: w,
			state,
			buf,
		}
	}

	#[inline]
	#[allow(dead_code)]
	fn buf(&self) -> &Vec<u8> {
		&self.buf
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

		loop {
			match &mut me.state {
				State::BuildingBuffer => {
					me.buf.extend_from_slice(src);
					me.state = State::WritingFromBuffer(0);
				}
				State::WritingFromBuffer(pos) => {
					ready!(poll_write_all(
						Pin::new(&mut me.inner),
						cx,
						pos,
						me.buf.as_slice()
					))?;
					// Change state and release the buffer.
					me.state = State::WritingDirectly;
					me.buf = Vec::new();
					return Poll::Ready(Ok(src.len()));
				}
				State::WritingDirectly => {
					return Pin::new(&mut me.inner).poll_write(cx, src);
				}
			}
		}
	}

	#[inline]
	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let me = self.get_mut();
		loop {
			match &mut me.state {
				State::BuildingBuffer => {
					// Immediately change state.
					me.state = State::WritingFromBuffer(0);
				}
				State::WritingFromBuffer(pos) => {
					ready!(poll_write_all(
						Pin::new(&mut me.inner),
						cx,
						pos,
						me.buf.as_slice()
					))?;
					// Change state and release the buffer.
					me.state = State::WritingDirectly;
					me.buf = Vec::new();
				}
				State::WritingDirectly => {
					return Pin::new(&mut me.inner).poll_flush(cx);
				}
			}
		}
	}

	#[inline]
	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let mut me = self.get_mut();
		ready!(Pin::new(&mut me).poll_flush(cx))?;
		Pin::new(&mut me.inner).poll_shutdown(cx)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::runtime::Runtime;

	#[test]
	fn test_lazy_init() {
		Runtime::new().unwrap().block_on(async {
			let short_vec = b"HelloWorld".repeat(10);
			let long_vec = b"SomeSuperLongString".repeat(1024);
			let inputs = [
				// Empty
				(Vec::new(), 0_usize),
				// Empty input should always be replaced with empty Vec no matter the capacity
				(Vec::with_capacity(1024), 0_usize),
				(short_vec.clone(), short_vec.capacity()),
				(long_vec.clone(), long_vec.capacity()),
			];
			for (input, expected_capacity) in inputs {
				let w = LazyWriteHalf::new(Vec::new(), input.clone());
				assert_eq!(&input, w.buf());
				assert_eq!(expected_capacity, w.buf().capacity())
			}
		})
	}

	#[test]
	fn test_lazy_write_multiple() {
		Runtime::new().unwrap().block_on(async {
			let header_data = b"This is some header data.".repeat(32);

			let inputs = [
				b"[Payload]".repeat(16),
				b"[two]".repeat(32),
				b"[3]".repeat(64),
			];
			let expected_outputs = {
				let mut buf = header_data.clone();
				let mut outputs = Vec::new();
				for input in &inputs {
					buf.extend(input);
					outputs.push(buf.clone());
				}
				outputs
			};
			let mut w = LazyWriteHalf::new(Vec::new(), header_data.clone());
			assert_eq!(
				w.buf(),
				&header_data,
				"before writing the internal buffer should be the same as data"
			);
			for (input, output) in inputs.iter().zip(expected_outputs.iter()) {
				w.write(input).await.unwrap();
				assert_eq!(&w.inner, output);
				assert!(
					w.buf().is_empty() && w.buf().capacity() == 0,
					"after writing the internal buffer should be EMPTY and not with len {} and capacity {}",
					w.buf().len(),
					w.buf().capacity()
				);
			}
		});
	}

	#[test]
	fn test_lazy_flush() {
		Runtime::new().unwrap().block_on(async {
			let header_data = b"This is some header data.".repeat(32);
			let expected = header_data.clone();
			let output = {
				let output_buf = Vec::new();
				let mut w = LazyWriteHalf::new(output_buf, header_data.clone());
				assert_eq!(
					w.buf(),
					&header_data,
					"before flushing the internal buffer should be the same as data"
				);
				assert_eq!(w.buf(), &header_data);
				w.flush().await.unwrap();
				assert!(
					w.buf().is_empty() && w.buf().capacity() == 0,
					"after flushing the internal buffer should be EMPTY and not with len {} and capacity {}",
					w.buf().len(),
					w.buf().capacity()
				);
				w.inner
			};
			assert_eq!(output, expected);
		});
	}
}
