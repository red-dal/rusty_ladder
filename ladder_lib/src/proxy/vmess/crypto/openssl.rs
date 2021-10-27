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

use openssl::symm::{Cipher, Crypter, Mode};
use super::{Block, AES_KEY_LEN};

/// Encrypt a single block using AES-128.
///
/// Decryptor cannot check whether `block` has been modified.
#[inline]
pub fn encrypt_aes_128(key: &Block, block: &mut Block) {
	do_cipher(Mode::Encrypt, key, block);
}

/// Decrypt a single block using AES-128.
///
/// There is NO guarantee that `block` has not been modified during
/// transmission.
#[inline]
pub fn decrypt_aes_128(key: &Block, block: &mut Block) {
	do_cipher(Mode::Decrypt, key, block);
}

fn do_cipher(mode: Mode, key: &Block, block: &mut Block) {
	let mut tmp_buf = [0_u8; AES_KEY_LEN * 2];
	let mut c =
		Crypter::new(Cipher::aes_128_ecb(), mode, key, None).expect("cannot initialize crypter");
	c.pad(false);
	let count = c.update(block, &mut tmp_buf).expect("cannot update");
	let rest = c.finalize(&mut tmp_buf[count..]).expect("cannot finalize");
	debug_assert_eq!(count + rest, block.len());
	block.copy_from_slice(&tmp_buf[..AES_KEY_LEN]);
}

pub struct Aes128CfbEncryptor {
	inner: CfbInternal,
}

impl Aes128CfbEncryptor {
	#[inline]
	pub fn new(key: &Block, iv: &Block) -> Self {
		Self {
			inner: CfbInternal::new(Mode::Encrypt, key, iv),
		}
	}

	#[inline]
	pub fn encrypt(&mut self, data: &mut [u8]) {
		self.inner.do_crypt(data);
	}
}

pub struct Aes128CfbDecrypter {
	inner: CfbInternal,
}

impl Aes128CfbDecrypter {
	#[inline]
	pub fn new(key: &Block, iv: &Block) -> Self {
		Self {
			inner: CfbInternal::new(Mode::Decrypt, key, iv),
		}
	}

	#[inline]
	pub fn decrypt(&mut self, data: &mut [u8]) {
		self.inner.do_crypt(data);
	}
}

struct CfbInternal {
	c: Crypter,
	buf: Vec<u8>,
	block_size: usize,
}

impl CfbInternal {
	fn new(mode: Mode, key: &Block, iv: &Block) -> Self {
		let t = Cipher::aes_128_cfb128();
		Self {
			c: Crypter::new(t, mode, key, Some(iv)).expect("cannot initialize_crypter"),
			buf: Vec::new(),
			block_size: t.block_size(),
		}
	}

	fn do_crypt(&mut self, data: &mut [u8]) {
		// Zero all memories.
		self.buf.clear();
		self.buf.resize(data.len() + self.block_size, 0);

		let count = self.c.update(data, &mut self.buf).expect("cannot update");
		let rest = self
			.c
			.finalize(&mut self.buf[count..])
			.expect("cannot finalize");
		debug_assert_eq!(count + rest, data.len());
		data.copy_from_slice(&self.buf[..data.len()]);
	}
}
