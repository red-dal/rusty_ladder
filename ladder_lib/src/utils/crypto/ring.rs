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
	use std::convert::TryInto;

	use crate::{prelude::BoxStdErr, utils::crypto::aead};

	use super::super::aead::{nonce, Decrypt, Encrypt};
	use ring::aead::{BoundKey, NonceSequence, OpeningKey, SealingKey, UnboundKey};

	struct NonceWrapper<N: nonce::Sequence>(N);

	impl<N> NonceSequence for NonceWrapper<N>
	where
		N: nonce::Sequence + Sized,
	{
		fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
			let val = *self.0.curr();
			self.0.update();
			Ok(ring::aead::Nonce::assume_unique_for_key(val))
		}
	}

	pub struct Encryptor<N: nonce::Sequence> {
		key: SealingKey<NonceWrapper<N>>,
	}

	impl<N: nonce::Sequence> Encrypt<N> for Encryptor<N> {
		fn new_encryptor(key: aead::Key, nonce: N) -> Result<Self, BoxStdErr> {
			Ok(Self {
				key: SealingKey::new(get_unbound_key(&key), NonceWrapper(nonce)),
			})
		}

		fn seal_inplace(
			&mut self,
			buf: &mut [u8],
			aad: &[u8],
		) -> Result<[u8; aead::TAG_LEN], BoxStdErr> {
			let tag = self
				.key
				.seal_in_place_separate_tag(ring::aead::Aad::from(aad), buf)
				.unwrap();
			Ok(tag.as_ref().try_into().unwrap())
		}
	}

	pub struct Decryptor<N: nonce::Sequence> {
		key: OpeningKey<NonceWrapper<N>>,
	}

	impl<N: nonce::Sequence> Decrypt<N> for Decryptor<N> {
		fn new_decryptor(key: aead::Key, nonce: N) -> Result<Self, BoxStdErr> {
			Ok(Self {
				key: OpeningKey::new(get_unbound_key(&key), NonceWrapper(nonce)),
			})
		}

		fn open_inplace<'b>(
			&mut self,
			buf: &'b mut [u8],
			aad: &[u8],
		) -> Result<&'b [u8], BoxStdErr> {
			let plain_text = self
				.key
				.open_in_place(ring::aead::Aad::from(aad), buf)
				.map_err(|_| "Unable to decrypt AEAD ciphertext")?;
			Ok(plain_text)
		}
	}

	fn get_unbound_key(key: &aead::Key) -> UnboundKey {
		let (algo, key) = match &key {
			aead::Key::Aes128Gcm(key) => (&ring::aead::AES_128_GCM, key.as_ref()),
			aead::Key::Aes256Gcm(key) => (&ring::aead::AES_256_GCM, key.as_ref()),
			aead::Key::ChaCha20Poly1305(key) => (&ring::aead::CHACHA20_POLY1305, key.as_ref()),
		};
		UnboundKey::new(algo, key).unwrap()
	}
}
