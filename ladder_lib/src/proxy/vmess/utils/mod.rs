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

pub(super) mod aead_codec;
pub(super) mod plain_codec;

mod error;

use std::num::NonZeroUsize;

use super::HeaderMode;
use crate::{non_zeros, prelude::*};
use digest::{Digest, ExtendableOutput, XofReader};
use md5::{digest, Md5};
use num_enum::TryFromPrimitive;
use sha2::Sha256;
use sha3::{Sha3XofReader, Shake128};
use uuid::Uuid;

pub const AUTH_ID_LEN: usize = 16;

pub(super) use error::Error;
pub type Key = [u8; 16];
pub type Iv = [u8; 16];
pub type AuthId = [u8; AUTH_ID_LEN];

const KEY_OFFSET_BYTES: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum AddrType {
	Ipv4 = 1,
	Name = 2,
	Ipv6 = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub enum SecurityType {
	// Documentation is wrong about these numbers
	#[cfg_attr(feature = "use_serde", serde(rename = "aes-128-cfb"))]
	Aes128Cfb = 1,
	#[cfg_attr(feature = "use_serde", serde(rename = "auto"))]
	Auto = 2,
	#[cfg_attr(feature = "use_serde", serde(rename = "aes-128-gcm"))]
	Aes128Gcm = 3,
	#[cfg_attr(feature = "use_serde", serde(rename = "chacha20-poly1305"))]
	Chacha20Poly1305 = 4,
	#[cfg_attr(feature = "use_serde", serde(rename = "none"))]
	None = 5,
	#[cfg_attr(feature = "use_serde", serde(rename = "zero"))]
	Zero = 6,
}

impl SecurityType {
	#[must_use]
	pub fn auto() -> Self {
		if cfg!(target_arch = "x86") || cfg!(target_arch = "x86_64") {
			SecurityType::Aes128Gcm
		} else {
			SecurityType::Chacha20Poly1305
		}
	}
}

impl Default for SecurityType {
	#[inline]
	fn default() -> Self {
		SecurityType::auto()
	}
}

pub trait LengthReader: Send + Sync + Unpin {
	fn length_buffer_size(&self) -> NonZeroUsize;
	fn read_length(&mut self, buf: &[u8]) -> Result<u16, BoxStdErr>;
	fn get_padding_len(&mut self) -> u16;
}

pub trait LengthWriter: Send + Sync + Unpin {
	fn write_length(&mut self, length: usize, buf: &mut Vec<u8>);
	fn get_padding_len(&mut self) -> u16;
}

pub struct ShakeLengthReader {
	buf: [u8; 2],
	shake_reader: Sha3XofReader,
	use_padding: bool,
}

impl ShakeLengthReader {
	pub const MAX_PADDING_LEN: u16 = 64;

	pub fn new(iv: &[u8; 16], use_padding: bool) -> Self {
		use sha3::digest::Update;
		let mut shake = Shake128::default();
		shake.update(iv.as_ref());
		Self {
			buf: [0_u8; 2],
			shake_reader: shake.finalize_xof(),
			use_padding,
		}
	}

	#[inline]
	fn update(&mut self) -> u16 {
		self.shake_reader.read(&mut self.buf);
		u16::from_be_bytes(self.buf)
	}
}

impl LengthReader for ShakeLengthReader {
	fn length_buffer_size(&self) -> NonZeroUsize {
		NonZeroUsize::from(*non_zeros::U8_2)
	}

	fn read_length(&mut self, buf: &[u8]) -> Result<u16, BoxStdErr> {
		let mask = self.update();
		// ignore the padding
		let (len_buf, _padding) = buf.split_at(2);
		let len = (&*len_buf).get_u16();
		let payload_len = len ^ mask;
		Ok(payload_len)
	}

	#[inline]
	fn get_padding_len(&mut self) -> u16 {
		if self.use_padding {
			let res = self.update() % Self::MAX_PADDING_LEN;
			return res;
		}
		0
	}
}

pub struct ShakeLengthWriter(ShakeLengthReader);

impl ShakeLengthWriter {
	pub const MAX_PADDING_LEN: u16 = ShakeLengthReader::MAX_PADDING_LEN;

	pub fn new(iv: &[u8; 16], use_padding: bool) -> Self {
		use sha3::digest::Update;
		let mut shake = Shake128::default();
		shake.update(iv.as_ref());
		Self(ShakeLengthReader {
			buf: [0_u8; 2],
			shake_reader: shake.finalize_xof(),
			use_padding,
		})
	}

	#[inline]
	fn update(&mut self) -> u16 {
		self.0.update()
	}
}

impl LengthWriter for ShakeLengthWriter {
	#[allow(clippy::cast_possible_truncation)]
	fn write_length(&mut self, length: usize, buf: &mut Vec<u8>) {
		// 16 bits should be enough for length in VMess.
		let length = length as u16;
		let mask = self.update();
		let length_res = mask ^ length;
		buf.put_u16(length_res);
	}

	#[inline]
	fn get_padding_len(&mut self) -> u16 {
		if self.0.use_padding {
			self.update() % Self::MAX_PADDING_LEN
		} else {
			0
		}
	}
}

pub struct PlainLengthReader;

impl LengthReader for PlainLengthReader {
	#[inline]
	fn length_buffer_size(&self) -> NonZeroUsize {
		NonZeroUsize::from(*non_zeros::U8_2)
	}

	#[inline]
	fn read_length(&mut self, buf: &[u8]) -> Result<u16, BoxStdErr> {
		let len = (&*buf).get_u16();
		Ok(len)
	}

	#[inline]
	fn get_padding_len(&mut self) -> u16 {
		0
	}
}

pub struct PlainLengthWriter;

impl LengthWriter for PlainLengthWriter {
	#[inline]
	#[allow(clippy::cast_possible_truncation)]
	fn write_length(&mut self, length: usize, buf: &mut Vec<u8>) {
		// 16 bits should be enough for length in VMess.
		buf.put_u16(length as u16);
	}

	#[inline]
	fn get_padding_len(&mut self) -> u16 {
		0
	}
}

#[inline]
pub fn md5(data: &[u8]) -> [u8; 16] {
	// iv = Md5(request.payload_iv)
	let mut md5 = Md5::default();
	md5.update(data);
	let res = md5.finalize();
	res.into()
}

// See more at <https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1a_hash>
pub fn fnv1a(x: &[u8]) -> u32 {
	const PRIME: u32 = 16_777_619;
	const OFFSET_BASIS: u32 = 2_166_136_261;
	let mut hash = OFFSET_BASIS;
	for byte in x {
		hash ^= u32::from(*byte);
		hash = hash.wrapping_mul(PRIME);
	}
	hash
}

pub fn new_cmd_key(id: &Uuid) -> [u8; 16] {
	let mut md5 = Md5::new();
	md5.update(id.as_bytes());
	md5.update(KEY_OFFSET_BYTES);
	md5.finalize().into()
}

#[cfg(feature = "vmess-legacy-auth")]
#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
pub fn new_auth(time: i64, uuid: &Uuid) -> Result<[u8; AUTH_ID_LEN], Error> {
	use hmac::{Hmac, Mac, NewMac};
	type HmacMd5 = Hmac<Md5>;
	let time = time.to_be_bytes();
	let mut hmac: HmacMd5 = HmacMd5::new_from_slice(uuid.as_bytes())
		.map_err(|e| Error::InvalidKeyLength(e.to_string().into()))?;
	hmac.update(time.as_ref());
	let auth = hmac.finalize().into_bytes().into();
	Ok(auth)
}

#[cfg(feature = "vmess-legacy-auth")]
pub fn new_request_key_iv(id: &Uuid, time: i64) -> (Key, Iv) {
	let request_key = new_cmd_key(id);

	// make iv
	let time = time.to_be_bytes();
	let mut md5 = Md5::new();
	md5.update(&time);
	md5.update(&time);
	md5.update(&time);
	md5.update(&time);
	let request_iv = md5.finalize();

	(request_key, request_iv.into())
}

pub fn new_response_key_and_iv(payload_key: &Key, payload_iv: &Iv, mode: HeaderMode) -> (Key, Iv) {
	match mode {
		#[cfg(feature = "vmess-legacy-auth")]
		HeaderMode::Legacy => {
			let mut md5 = Md5::new();
			md5.update(payload_key);
			let response_key = md5.finalize_reset();
			md5.update(payload_iv);
			let response_iv = md5.finalize();
			(response_key.into(), response_iv.into())
		}
		HeaderMode::Aead => {
			// use sha256 instead of md5
			let mut sha256 = Sha256::new();
			sha256.update(payload_key);
			let response_key = sha256.finalize_reset();
			sha256.update(payload_iv);
			let response_iv = sha256.finalize_reset();
			(to_arr_16(response_key), to_arr_16(response_iv))
		}
	}
}

pub fn generate_chacha20_key(key: &Key, output: &mut [u8; 32]) {
	let tmp = md5(key);
	output[..16].copy_from_slice(&tmp);
	let tmp = md5(&tmp);
	output[16..].copy_from_slice(&tmp);
}

pub fn to_arr_16<T: AsRef<[u8]>>(value: T) -> [u8; 16] {
	let mut result = [0_u8; 16];
	result.copy_from_slice(&value.as_ref()[..16]);
	result
}
