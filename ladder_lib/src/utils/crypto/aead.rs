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

// #[path = "rust_crypto.rs"]
// mod inner;

use crate::{non_zeros, prelude::BoxStdErr};
use std::num::NonZeroU8;

pub use super::inner_aead::{Decryptor, Encryptor};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Algorithm {
	Aes128Gcm,
	Aes256Gcm,
	ChaCha20Poly1305,
}

impl Algorithm {
	#[inline]
	#[allow(dead_code)]
	pub fn key_size(self) -> NonZeroU8 {
		match self {
			Self::Aes128Gcm => non_zeros::u8!(16),
			Self::Aes256Gcm | Self::ChaCha20Poly1305 => non_zeros::u8!(32),
		}
	}
}

#[allow(dead_code)]
pub enum Key {
	Aes128Gcm([u8; 16]),
	Aes256Gcm([u8; 32]),
	ChaCha20Poly1305([u8; 32]),
}

impl Key {
	#[inline]
	pub fn as_slice(&self) -> &[u8] {
		match self {
			Key::Aes128Gcm(key) => key,
			Key::Aes256Gcm(key) | Key::ChaCha20Poly1305(key) => key,
		}
	}
}

impl AsRef<[u8]> for Key {
	#[inline]
	fn as_ref(&self) -> &[u8] {
		self.as_slice()
	}
}

pub trait Decrypt<N: nonce::Sequence>: Sized {
	fn new_decryptor(key: Key, nonce: N) -> Result<Self, BoxStdErr>;
	fn open_inplace<'b>(&mut self, buf: &'b mut [u8], aad: &[u8]) -> Result<&'b [u8], BoxStdErr>;
}

pub trait Encrypt<N: nonce::Sequence>: Sized {
	fn new_encryptor(key: Key, nonce: N) -> Result<Self, BoxStdErr>;
	fn seal_inplace(&mut self, buf: &mut [u8], aad: &[u8]) -> Result<[u8; TAG_LEN], BoxStdErr>;

	#[inline]
	fn seal_inplace_append_tag(
		&mut self,
		start_pos: usize,
		buf: &mut Vec<u8>,
		aad: &[u8],
	) -> Result<(), BoxStdErr> {
		let tag = self.seal_inplace(&mut buf[start_pos..], aad)?;
		buf.extend_from_slice(&tag);
		Ok(())
	}
}

pub mod nonce {
	use super::NONCE_LEN;

	// Nonce with all 0s.
	#[allow(dead_code)]
	pub const EMPTY: &[u8; NONCE_LEN] = &[0_u8; NONCE_LEN];

	#[allow(clippy::module_name_repetitions)]
	pub trait Sequence {
		fn curr(&self) -> &[u8; NONCE_LEN];
		fn update(&mut self);
	}

	/// A nonce sequence that treats nonce as an unsigned small-endian integer and
	/// increase its value by 1 when `update` function is called.
	pub struct CounterSequence {
		nonce: [u8; NONCE_LEN],
	}

	impl CounterSequence {
		#[inline]
		pub fn new(nonce: &[u8; NONCE_LEN]) -> Self {
			Self { nonce: *nonce }
		}
	}

	impl Default for CounterSequence {
		fn default() -> Self {
			Self {
				nonce: [0_u8; NONCE_LEN],
			}
		}
	}

	impl Sequence for CounterSequence {
		#[inline]
		fn curr(&self) -> &[u8; NONCE_LEN] {
			&self.nonce
		}

		#[inline]
		fn update(&mut self) {
			increase(&mut self.nonce);
		}
	}

	#[inline]
	pub fn increase(nonce: &mut [u8; NONCE_LEN]) {
		for i in nonce {
			if std::u8::MAX == *i {
				*i = 0;
			} else {
				*i += 1;
				return;
			}
		}
	}
}
