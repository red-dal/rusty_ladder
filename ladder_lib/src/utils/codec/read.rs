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
use crate::{prelude::*, utils::poll_read_exact};
use futures::ready;
use std::{
	io,
	num::NonZeroUsize,
	pin::Pin,
	task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

pub trait Decode: Send + Sync + Unpin {
	fn expected_len(&self) -> Option<NonZeroUsize>;

	/// Returns `Ok(true)` if decoded successfully.
	///
	/// Returns `Ok(false)` if more bytes are needed.
	fn decode_inplace(&mut self, buf: &mut Vec<u8>) -> Result<bool, BoxStdErr>;
}

impl<T: Decode> Decode for Box<T> {
	#[inline]
	fn expected_len(&self) -> Option<NonZeroUsize> {
		self.as_ref().expected_len()
	}

	#[inline]
	fn decode_inplace(&mut self, buf: &mut Vec<u8>) -> Result<bool, BoxStdErr> {
		self.as_mut().decode_inplace(buf)
	}
}

/// State of the [`CodecReadHelper`].
/// Must be with `FindingLength` when initialized.
enum DecodeState {
	/// Trying to find out what's the length of next frame.
	FindingLength,
	/// Trying to read and fill the buffer.
	///
	/// Buffer must be resize first.
	ReadingExact {
		pos: usize,
	},
	/// Trying to read some bytes into buffer.
	///
	/// Buffer must be resize first,
	/// after reading the buffer will be truncated.
	ReadingSome,
	/// Trying to decode the buffer.
	Decoding,
	Closed,
}

struct CodecReadHelper<D: Decode> {
	decoder: D,
	state: DecodeState,
}

impl<D: Decode> CodecReadHelper<D> {
	pub fn new(decoder: D) -> Self {
		Self {
			decoder,
			state: DecodeState::FindingLength,
		}
	}

	/// Attempt to read and decode bytes into `buf`.
	///
	/// The following may be returned:
	/// - `Poll::Ready(Ok(()))` means data was read and placed into `buf`.
	///    All existing bytes in `buf` will be overwritten.
	///    If no data is read (`buf.is_empty()`), EOF has been reached.
	///    
	/// - `Poll::Pending` is equal to the one in [`AsyncRead::poll_read`].
	///
	/// - `Poll::Ready(Err(e))` means there is an IO/decoding error.
	///
	/// If any error occurred or EOF was reached,
	/// the `self.state` will be set to [`DecodeState::Closed`].
	pub fn poll_read_decode<R>(
		&mut self,
		mut reader: Pin<&mut R>,
		cx: &mut Context,
		buf: &mut Vec<u8>,
	) -> Poll<io::Result<()>>
	where
		R: AsyncRead + Unpin,
	{
		// State graph:
		//
		//                              !buf.is_empty()&&Ok(true)
		//                      ┌───────────────────────────────────┐
		//                      │       return Poll::Ready(Ok(())); │
		//                      │                                   │
		//                      │                                   │
		// ┌────────────────────▼───┐                               │
		// │    FindingLength       │                               │
		// │ decoder.expected_len() ◄──────Ok(false)───┐            │
		// └───┬────────────────────┘                  │            │
		//     │                                       │            │
		//     │            ┌──────────────┐         ┌─┴────────────┴─┐
		//     ├─Some(len)──► ReadingExact ├─────────►                │
		//     │            └──────────────┘         │                │
		//     │                                     │   Decoding     │
		//     │                                     │dec.decode(buf) │
		//     │             ┌─────────────┐         │                │
		//     └───None──────► ReadingSome ├─────────►                │
		//                   └─────────────┘         └────────────────┘

		// EOF is reached if `buf` is empty after dec.decode returns Ok(true).

		// If there is any error (IO or decoding), or EOF was reached
		// the state must be set to `Closed` and prevent any future polling.

		// Everytime a Poll::Ready(Ok(())) is returned,
		// the state must be `FindingLength`.
		loop {
			match &mut self.state {
				DecodeState::FindingLength => {
					if let Some(len) = self.decoder.expected_len() {
						// Next try to read a specific amount of bytes.
						buf.resize(len.get(), 0);
						self.state = DecodeState::ReadingExact { pos: 0 };
						trace!("Frame length: {}", buf.len());
					} else {
						// Next try to read some amount of bytes.
						buf.resize(BUFFER_CAPACITY, 0);
						self.state = DecodeState::ReadingSome;
						trace!("Frame length: None");
					}
				}
				DecodeState::ReadingExact { pos } => {
					trace!("Trying to read exact {} bytes", buf.len());
					let n = match ready!(poll_read_exact(reader.as_mut(), cx, buf, pos)) {
						Ok(n) => n,
						Err(e) => {
							debug!(
								"Error occurred while trying to read {} bytes ({})",
								buf.len(),
								e
							);
							self.state = DecodeState::Closed;
							return Err(e).into();
						}
					};
					buf.truncate(n);
					// EOF is reached if n is 0,
					// but this will be handled in Decoding state,
					// so ignore it now.

					// Next try to decode the bytes.
					trace!("Done reading exact {} bytes into buf", buf.len());
					self.state = DecodeState::Decoding;
				}
				DecodeState::ReadingSome => {
					trace!("Trying to read some bytes in buf ({} bytes)", buf.len());

					let mut read_buf = ReadBuf::new(buf.as_mut_slice());
					if let Err(e) = ready!(reader.as_mut().poll_read(cx, &mut read_buf)) {
						self.state = DecodeState::Closed;
						debug!("Error occurred while trying to read some bytes ({})", e);
						// Clean up buffer.
						buf.clear();
						buf.shrink_to_fit();
						return Err(e).into();
					}
					let n = read_buf.filled().len();
					buf.truncate(n);
					// EOF is reached if n is 0,
					// but this will be handled in Decoding state,
					// so ignore it now.

					trace!("Done reading {} bytes into buf", buf.len());
					// Next try to decode the bytes.
					self.state = DecodeState::Decoding;
				}
				DecodeState::Decoding => {
					trace!("Decoding buf ({} bytes)...", buf.len());

					let enough_bytes = self.decoder.decode_inplace(buf).map_err(|e| {
						self.state = DecodeState::Closed;
						io::Error::new(io::ErrorKind::InvalidData, e)
					})?;

					if enough_bytes {
						trace!("Decoded successfully, buf.len: {}", buf.len());
						// If there are enough bytes to decode,
						// returns immediately.
						self.state = if buf.is_empty() {
							// Empty buf means that decoder thinks EOF is reached.
							trace!("Reached EOF after successfully decoded.");
							DecodeState::Closed
						} else {
							DecodeState::FindingLength
						};
						return Ok(()).into();
					}

					trace!("Need more bytes.");
					self.state = DecodeState::FindingLength;
				}
				DecodeState::Closed => {
					return Err(io::Error::new(
						io::ErrorKind::BrokenPipe,
						"ReadHelper already closed.",
					))
					.into();
				}
			}
		}
	}
}

#[derive(Debug)]
enum State {
	/// This means reader is polling the internal [`CodecReadHelper`].
	ReadingDecoding,
	/// This means the internal [`CodecReadHelper`] has successfully
	/// read and decoded some bytes into buffer.
	///
	/// `pos` is the current start position of the buffer's remaining.
	///
	/// When first enter this state, `pos` must be zero.
	Buffering { pos: usize },
	/// This means the reader has been closed.
	Closed,
}

/// A reader that takes bytes from another [`AsyncRead`]
/// and process it with [`Decode`].
///
/// To access the original [`AsyncRead`], just use the `r` field directly.
pub struct FrameReadHalf<D: Decode, R: AsyncRead + Unpin> {
	pub r: R,
	codec_reader: CodecReadHelper<D>,
	state: State,
	buf: Vec<u8>,
}

impl<D, R> FrameReadHalf<D, R>
where
	D: Decode,
	R: AsyncRead + Unpin,
{
	#[inline]
	pub fn new(decoder: D, r: R) -> Self {
		Self::with_capacity(decoder, r, BUFFER_CAPACITY)
	}

	pub fn with_capacity(decoder: D, r: R, cap: usize) -> Self {
		Self {
			r,
			buf: Vec::with_capacity(cap),
			codec_reader: CodecReadHelper::new(decoder),
			state: State::ReadingDecoding,
		}
	}
}

impl<D, R> AsyncRead for FrameReadHalf<D, R>
where
	D: Decode,
	R: AsyncRead + Unpin,
{
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		read_buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		// Try to fill internal buffer before copying data to read_buf.
		// Unlike BufReader's implementation, filling internal buffer cannot be skipped.
		let data = ready!(self.as_mut().poll_fill_buf(cx))?;

		let amt = std::cmp::min(data.len(), read_buf.remaining());
		read_buf.put_slice(&data[..amt]);
		self.as_mut().consume(amt);
		Poll::Ready(Ok(()))
	}
}

impl<D, R> AsyncBufRead for FrameReadHalf<D, R>
where
	D: Decode,
	R: AsyncRead + Unpin,
{
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
		let me = self.get_mut();
		loop {
			trace!("FrameReadHalf poll_fill_buf with state {:?}", me.state);
			match &mut me.state {
				State::ReadingDecoding => {
					if let Err(e) = ready!(me.codec_reader.poll_read_decode(
						Pin::new(&mut me.r),
						cx,
						&mut me.buf
					)) {
						me.state = State::Closed;
						return Err(e).into();
					}
					// Empty buf means EOF.
					if me.buf.is_empty() {
						me.state = State::Closed;
						// Release memory.
						me.buf = Vec::new();
						return Ok(me.buf.as_slice()).into();
					}
					// Next starts buffering.
					me.state = State::Buffering { pos: 0 };
				}
				State::Buffering { pos } => {
					if *pos == me.buf.len() {
						// Buffer empty, try to fill it.
						me.state = State::ReadingDecoding;
					} else {
						return Ok(&me.buf[*pos..]).into();
					}
				}
				State::Closed => return Err(io::ErrorKind::BrokenPipe.into()).into(),
			}
		}
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		let me = self.get_mut();
		if let State::Buffering { pos } = &mut me.state {
			*pos += amt;
			debug_assert!(*pos <= me.buf.len());
			if *pos == me.buf.len() {
				me.state = State::ReadingDecoding;
			}
		} else {
            // TODO: Find out where this can happen.
			panic!("Cannot consume when FrameReadState is not Buffering. poll_fill_buf must be polled first.");
		}
	}
}
