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

use crate::utils::crypto::aead::{nonce::CounterSequence, Decrypt, Decryptor, Encrypt, Encryptor, Key};

pub(super) mod auth_id;
pub(super) mod kdf;

#[inline]
pub fn new_aead_encryptor(key: &[u8; 16], iv: &[u8; 12]) -> Encryptor<CounterSequence> {
	Encryptor::new_encryptor(Key::Aes128Gcm(*key), CounterSequence::new(iv)).unwrap()
}

#[inline]
pub fn new_aead_decryptor(key: &[u8; 16], iv: &[u8; 12]) -> Decryptor<CounterSequence> {
	Decryptor::new_decryptor(Key::Aes128Gcm(*key), CounterSequence::new(iv)).unwrap()
}
