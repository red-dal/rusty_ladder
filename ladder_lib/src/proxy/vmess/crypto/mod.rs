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


#[cfg_attr(feature = "__crypto_openssl", path = "openssl.rs")]
#[cfg_attr(feature = "__crypto_crypto_ring", path = "rust_crypto.rs")]
mod inner;

pub const AES_KEY_LEN: usize = 16;
pub type Block = [u8; AES_KEY_LEN];

/// Encrypt a single block using AES-128.
///
/// Decryptor cannot check whether `block` has been modified.
#[inline]
pub fn encrypt_aes_128(key: &Block, block: &mut Block) {
    inner::encrypt_aes_128(key, block);
}

/// Decrypt a single block using AES-128.
///
/// There is NO guarantee that `block` has not been modified during
/// transmission.
#[inline]
#[allow(dead_code)]
pub fn decrypt_aes_128(key: &Block, block: &mut Block) {
    inner::decrypt_aes_128(key, block);
}
