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

use std::num::NonZeroUsize;

use super::{
	Iv, LengthReader, LengthWriter, PlainLengthReader, PlainLengthWriter, ShakeLengthReader,
	ShakeLengthWriter,
};
use crate::{
	prelude::*,
	utils::codec::{Decode, Encode},
};

pub type PlainLenEncoder = Encoder<PlainLengthWriter>;
pub type PlainLenDecoder = Decoder<PlainLengthReader>;
pub type ShakeLenEncoder = Encoder<ShakeLengthWriter>;
pub type ShakeLenDecoder = Decoder<ShakeLengthReader>;

pub fn new_plain_enc() -> PlainLenEncoder {
	Encoder {
		lw: PlainLengthWriter,
		lazy_buf: Vec::new(),
	}
}

pub fn new_plain_dec() -> PlainLenDecoder {
	Decoder::new(PlainLengthReader)
}

pub fn new_shake_enc(iv: &Iv, use_padding: bool) -> ShakeLenEncoder {
	Encoder {
		lw: ShakeLengthWriter::new(iv, use_padding),
		lazy_buf: Vec::new(),
	}
}

pub fn new_shake_dec(iv: &Iv, use_padding: bool) -> ShakeLenDecoder {
	Decoder::new(ShakeLengthReader::new(iv, use_padding))
}

pub struct Encoder<E: LengthWriter> {
	lw: E,
	pub lazy_buf: Vec<u8>,
}

impl<E: LengthWriter> Encode for Encoder<E> {
	fn encode_into(&mut self, src: &[u8], buf: &mut Vec<u8>) -> Result<(), BoxStdErr> {
		buf.clear();
		if !self.lazy_buf.is_empty() {
			trace!(
				"Putting lazy_buf ({} bytes) into buf...",
				self.lazy_buf.len()
			);
			buf.put_slice(&self.lazy_buf);
			self.lazy_buf = Vec::new();
		}
		trace!(
			"Encoding src ({} bytes) into buf ({} bytes already)...",
			src.len(),
			buf.len()
		);
		// len: 2 bytes
		// src: len bytes
		self.lw.write_length(src.len(), buf);
		buf.put_slice(src);
		Ok(())
	}
}

enum DecState {
	Length,
	Payload,
}

pub struct Decoder<LR: LengthReader> {
	lr: LR,
	curr_len: NonZeroUsize,
	state: DecState,
}

impl<LR: LengthReader> Decoder<LR> {
	fn new(lr: LR) -> Self {
		let curr_len = lr.length_buffer_size();
		Self {
			lr,
			curr_len,
			state: DecState::Length,
		}
	}
}

impl<LR: LengthReader> Decode for Decoder<LR> {
	fn expected_len(&self) -> Option<NonZeroUsize> {
		Some(self.curr_len)
	}

	fn decode_inplace(&mut self, buf: &mut Vec<u8>) -> Result<bool, BoxStdErr> {
		match &self.state {
			DecState::Length => {
				trace!("Decoding length.");

				if buf.is_empty() {
					// Do nothing for EOF.
					return Ok(true);
				}

				if let Some(len) = NonZeroUsize::new(self.lr.read_length(&buf[..2])?.into()) {
					trace!("Payload length: {}.", len);
					self.curr_len = len;
					self.state = DecState::Payload;
					Ok(false)
				} else {
					// Payload with size of 0 means EOF.
					trace!("Reached EOF when decoding length.");
					buf.clear();
					Ok(true)
				}
			}
			DecState::Payload => {
				if buf.is_empty() {
					// EOF cannot happened in Payload state.
					return Err("EOF is reached while reading VMess payload in plain_codec".into());
				}

				debug_assert_eq!(buf.len(), self.curr_len.get());
				self.curr_len = self.lr.length_buffer_size();
				trace!(
					"Decoding payload ({} bytes), curr_len: {}",
					buf.len(),
					self.curr_len
				);
				self.state = DecState::Length;
				// Do nothing about the payload.
				Ok(true)
			}
		}
	}
}
