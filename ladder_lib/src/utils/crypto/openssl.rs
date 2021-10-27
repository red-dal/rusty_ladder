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

pub mod aead {
	use super::super::aead::{Decrypt, Encrypt, Key, nonce::Sequence, TAG_LEN};
	use crate::prelude::BoxStdErr;
	use openssl::symm::{Cipher, Crypter, Mode};

	struct Handler<N> {
		cipher: Cipher,
		key: Key,
		nonce: N,
		tmp_buf: Vec<u8>,
	}

	impl<N: Sequence> Handler<N> {
		#[inline]
		pub fn new(key: Key, nonce: N) -> Self {
			let cipher = get_cipher(&key);
			Self {
				cipher,
				nonce,
				key,
				tmp_buf: Vec::new(),
			}
		}

		fn seal(&mut self, buf: &mut [u8], aad: &[u8]) -> Result<[u8; TAG_LEN], BoxStdErr> {
			let tmp_buf = &mut self.tmp_buf;
			tmp_buf.resize(buf.len() + self.cipher.block_size(), 0);

			let tag = {
				let plain_text = &*buf;
				// Prepare.
				let mut c = Crypter::new(
					self.cipher,
					Mode::Encrypt,
					self.key.as_slice(),
					Some(self.nonce.curr()),
				)?;
				// Set AAD.
				c.aad_update(aad)?;
				// Encrypt plain_text into tmp_buf.
				let count = c.update(plain_text, tmp_buf)?;
				let rest = c.finalize(&mut tmp_buf[count..])?;
				assert_eq!(count + rest, plain_text.len());
				// Get tag.
				let mut tag = [0_u8; TAG_LEN];
				c.get_tag(&mut tag)?;
				tag
			};
			buf.copy_from_slice(&tmp_buf[..buf.len()]);
			self.nonce.update();
			Ok(tag)
		}

		fn open<'b>(&mut self, buf: &'b mut [u8], aad: &[u8]) -> Result<&'b [u8], BoxStdErr> {
			let (text, tag) = buf.split_at_mut(buf.len() - TAG_LEN);
			let tag = &*tag;

			let tmp_buf = &mut self.tmp_buf;
			tmp_buf.resize(text.len() + self.cipher.block_size(), 0);

			{
				let cipher_text = &*text;
				// Prepare.
				let mut c = Crypter::new(
					self.cipher,
					Mode::Decrypt,
					self.key.as_slice(),
					Some(self.nonce.curr()),
				)?;
				// Set AAD.
				c.aad_update(aad)?;
				// Set tag.
				c.set_tag(tag)?;
				// Decrypt cipher_text into tmp_buf
				let count = c.update(cipher_text, tmp_buf)?;
				let rest = c.finalize(&mut tmp_buf[count..])?;
				assert_eq!(count + rest, cipher_text.len());
			}
			text.copy_from_slice(&tmp_buf[..text.len()]);
			self.nonce.update();
			Ok(text)
		}
	}

	pub struct Encryptor<N>(Handler<N>);

	impl<N: Sequence> Encrypt<N> for Encryptor<N> {
		#[inline]
		fn new_encryptor(key: Key, nonce: N) -> Result<Self, BoxStdErr> {
			Ok(Self(Handler::new(key, nonce)))
		}

		#[inline]
		fn seal_inplace(&mut self, buf: &mut [u8], aad: &[u8]) -> Result<[u8; TAG_LEN], BoxStdErr> {
			self.0.seal(buf, aad)
		}
	}

	pub struct Decryptor<N>(Handler<N>);

	impl<N: Sequence> Decrypt<N> for Decryptor<N> {
		#[inline]
		fn new_decryptor(key: Key, nonce: N) -> Result<Self, BoxStdErr> {
			Ok(Self(Handler::new(key, nonce)))
		}

		#[inline]
		fn open_inplace<'b>(&mut self, buf: &'b mut [u8], aad: &[u8]) -> Result<&'b [u8], BoxStdErr> {
			self.0.open(buf, aad)
		}
	}

	fn get_cipher(key: &Key) -> Cipher {
		match key {
			Key::Aes128Gcm(_) => Cipher::aes_128_gcm(),
			Key::Aes256Gcm(_) => Cipher::aes_256_gcm(),
			Key::ChaCha20Poly1305(_) => Cipher::chacha20_poly1305(),
		}
	}
}