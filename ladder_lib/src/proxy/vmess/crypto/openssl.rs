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

use super::{Block, AES_KEY_LEN};
use openssl::symm::{Cipher, Crypter, Mode};

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
