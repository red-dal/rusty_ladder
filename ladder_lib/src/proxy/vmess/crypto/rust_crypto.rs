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

use super::Block;
use aes::{Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use cfb_mode::cipher::{AsyncStreamCipher, NewCipher};
use cfb_mode::Cfb;

type AesCfb = Cfb<Aes128>;

/// Encrypt a single block using AES-128.
///
/// Decryptor cannot check whether `block` has been modified.
#[inline]
pub fn encrypt_aes_128(key: &Block, block: &mut Block) {
	Aes128::new(key.into()).encrypt_block(block.into());
}

/// Decrypt a single block using AES-128.
///
/// There is NO guarantee that `block` has not been modified during
/// transmission.
#[inline]
pub fn decrypt_aes_128(key: &Block, block: &mut Block) {
	Aes128::new(key.into()).decrypt_block(block.into());
}

pub struct Aes128CfbEncryptor {
	inner: AesCfb,
}

impl Aes128CfbEncryptor {
	#[inline]
	pub fn new(key: &Block, iv: &Block) -> Self {
		Self {
			inner: AesCfb::new(key.into(), iv.into()),
		}
	}

	#[inline]
	pub fn encrypt(&mut self, data: &mut [u8]) {
		self.inner.encrypt(data);
	}
}

pub struct Aes128CfbDecrypter {
	inner: AesCfb,
}

impl Aes128CfbDecrypter {
	#[inline]
	pub fn new(key: &Block, iv: &Block) -> Self {
		Self {
			inner: AesCfb::new(key.into(), iv.into()),
		}
	}

	#[inline]
	pub fn decrypt(&mut self, data: &mut [u8]) {
		self.inner.decrypt(data);
	}
}
