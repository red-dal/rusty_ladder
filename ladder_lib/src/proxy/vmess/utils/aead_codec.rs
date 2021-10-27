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

use super::{Iv, LengthReader, LengthWriter};
use crate::{
	prelude::*,
	utils::codec::{Decode, Encode},
	utils::{
		crypto::aead::{Decrypt, Decryptor, Encrypt, Encryptor, nonce, NONCE_LEN, TAG_LEN},
		read_u16,
	},
};
use rand::thread_rng;
use std::num::{NonZeroU16, NonZeroUsize};

#[derive(Clone)]
pub struct VmessNonceSequence {
	nonce: [u8; NONCE_LEN],
}

impl VmessNonceSequence {
	pub fn new(iv: &Iv) -> Self {
		let nonce = make_aead_iv(iv);
		trace!("Vmess AEAD nonce: {:?}", nonce);
		Self { nonce }
	}
}

#[inline]
fn make_aead_iv(iv: &Iv) -> [u8; NONCE_LEN] {
	let mut res = [0_u8; NONCE_LEN];
	res[2..12].copy_from_slice(&iv[2..12]);
	res
}

impl nonce::Sequence for VmessNonceSequence {
	#[inline]
	fn curr(&self) -> &[u8; NONCE_LEN] {
		&self.nonce
	}

	#[inline]
	fn update(&mut self) {
		let count_buf = &mut self.nonce[..2];
		let mut count = read_u16(count_buf);
		count = count.wrapping_add(1);
		count_buf.copy_from_slice(&count.to_be_bytes());
	}
}

pub struct Encoder<LW: LengthWriter> {
	enc: Encryptor<VmessNonceSequence>,
	lw: LW,
	pub lazy_buf: Vec<u8>,
}

impl<LW> Encoder<LW>
where
	LW: LengthWriter,
{
	pub fn new(enc: Encryptor<VmessNonceSequence>, lw: LW) -> Self {
		Self {
			enc,
			lw,
			lazy_buf: Vec::new(),
		}
	}

	fn priv_encode(&mut self, src: &[u8], buf: &mut Vec<u8>) -> Result<(), BoxStdErr> {
		let payload_len = src.len() + TAG_LEN;
		let padding_len = usize::from(self.lw.get_padding_len());
		trace!(
			"Encode payload ({} bytes, {} bytes with tag), and padding ({} bytes) into buffer",
			src.len(),
			payload_len,
			padding_len,
		);
		// Payload length
		self.lw.write_length(padding_len + payload_len, buf);

		// Payload
		let payload_start_pos = buf.len();
		buf.put_slice(src);
		let tag = self.enc.seal_inplace(&mut buf[payload_start_pos..], &[])?;
		buf.put_slice(&tag);

		// Padding
		if padding_len > 0 {
			let padding_start = buf.len();
			buf.resize(buf.len() + padding_len, 0);
			let mut rng = thread_rng();
			rng.fill_bytes(&mut buf[padding_start..]);
		}

		Ok(())
	}
}

impl<LE> Encode for Encoder<LE>
where
	LE: LengthWriter,
{
	#[inline]
	fn encode_into(&mut self, src: &[u8], buf: &mut Vec<u8>) -> Result<(), BoxStdErr> {
		buf.clear();
		if !self.lazy_buf.is_empty() {
			trace!(
				"Taking bytes from lazy_buf ({} bytes) into buf",
				self.lazy_buf.len()
			);
			buf.put_slice(&self.lazy_buf);
			self.lazy_buf = Vec::new();
		}
		self.priv_encode(src, buf)
	}
}

enum DecodeState {
	Length,
	/// `len` is the length of payload INCLUDING padding.
	Payload {
		len: NonZeroU16,
		padding_len: u16,
	},
}

pub struct Decoder<L: LengthReader> {
	decryptor: Decryptor<VmessNonceSequence>,
	lr: L,
	state: DecodeState,
}

impl<L> Decoder<L>
where
	L: LengthReader,
{
	pub fn new(decryptor: Decryptor<VmessNonceSequence>, lr: L) -> Self {
		Self {
			decryptor,
			lr,
			state: DecodeState::Length,
		}
	}
}

impl<LD> Decode for Decoder<LD>
where
	LD: LengthReader,
{
	fn expected_len(&self) -> Option<NonZeroUsize> {
		match &self.state {
			DecodeState::Length => Some(self.lr.length_buffer_size()),
			DecodeState::Payload {
				len,
				padding_len: _,
			} => Some((*len).into()),
		}
	}

	fn decode_inplace(&mut self, buf: &mut Vec<u8>) -> Result<bool, BoxStdErr> {
		match &self.state {
			DecodeState::Length => {
				if buf.is_empty() {
					// If EOF has been reahed, do nothing.
					return Ok(true);
				}

				let padding_len = self.lr.get_padding_len();
				let len = self.lr.read_length(&buf[..2])?;
				trace!("AEAD payload padding_len: {}, length: {}", padding_len, len);

				NonZeroU16::new(len).map_or_else(
					|| {
						// len is 0 means EOF has been reached.
						buf.clear();
						Ok(true)
					},
					|len| {
						// More bytes are needed to decode payload.
						self.state = DecodeState::Payload { len, padding_len };
						Ok(false)
					},
				)
			}
			DecodeState::Payload { len, padding_len } => {
				trace!(
					"Decoding AEAD payload with padding_len: {}, length: {} ...",
					padding_len,
					len
				);
				if buf.is_empty() {
					return Err("EOF is reached while reading VMess payload".into());
				}

				if buf.len() != usize::from(len.get()) {
					return Err(
						format!("length of buf ({} bytes) must be {}", buf.len(), len).into(),
					);
				}

				let pad_len = *padding_len as usize;

				let msg = || {
					format!(
						"VMess payload too small ({} bytes), must be larger than padding_len({} bytes) + TAG_LEN({} bytes)",
						buf.len(),
						pad_len,
						TAG_LEN
					)
				};

				let payload_len = buf.len().checked_sub(pad_len + TAG_LEN).ok_or_else(msg)?;

				// Not EOF
				if payload_len > 0 {
					// Ignore padding when decoding.
					self.decryptor
						.open_inplace(&mut buf[..payload_len + TAG_LEN], &[])?;
					buf.truncate(payload_len);
				}

				self.state = DecodeState::Length;

				trace!("Done decoding AEAD payload, buf.len: {}", buf.len());

				Ok(true)
			}
		}
	}
}
