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

use super::super::{
	aead_header::{kdf, new_aead_decryptor, new_aead_encryptor},
	utils::Error,
};
use super::{Iv, Key};
use crate::utils::{append_mut, crypto::aead::{Decrypt, Encrypt}};
use crate::{prelude::*, utils::read_u16};

const AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";

const AEAD_RESP_HEADER_KEY: &[u8] = b"AEAD Resp Header Key";
const AEAD_RESP_HEADER_IV: &[u8] = b"AEAD Resp Header IV";

#[allow(dead_code)]
pub fn open_len(buf: &mut [u8], response_key: &Key, response_iv: &Iv) -> Result<usize, Error> {
	debug_assert_eq!(buf.len(), 18);

	let key = kdf::new_16(response_key, [AEAD_RESP_HEADER_LEN_KEY].iter().copied());
	let iv = kdf::new_12(response_iv, [AEAD_RESP_HEADER_LEN_IV].iter().copied());

	// correct key size, should be ok to unwrap
	let mut decryptor = new_aead_decryptor(&key, &iv);

	decryptor
		.open_inplace(buf, &[])
		.map_err(Error::new_crypto)?;

	let len = read_u16(&buf[..2]);

	Ok(len as usize)
}

#[allow(dead_code)]
pub fn open_payload<'a>(
	buf: &'a mut [u8],
	response_key: &Key,
	response_iv: &Iv,
) -> Result<&'a [u8], Error> {
	debug_assert!(buf.len() > 16);
	let key = kdf::new_16(response_key, [AEAD_RESP_HEADER_KEY].iter().copied());
	let iv = kdf::new_12(response_iv, [AEAD_RESP_HEADER_IV].iter().copied());

	let buf = new_aead_decryptor(&key, &iv)
		.open_inplace(buf, &[])
		.map_err(Error::new_crypto)?;

	Ok(buf)
}

pub fn seal_response(response_buf: &[u8], response_key: &Key, response_iv: &Iv) -> Vec<u8> {
	let mut result = Vec::with_capacity(64);
	// Encrypting response length.
	{
		let buf_len = u16::try_from(response_buf.len()).expect("response_buf too large");
		result.put_u16(buf_len);
		// This is not well documented in v2ray.
		let key = kdf::new_16(response_key, [AEAD_RESP_HEADER_LEN_KEY].iter().copied());
		let iv = kdf::new_12(response_iv, [AEAD_RESP_HEADER_LEN_IV].iter().copied());

		let tag = new_aead_encryptor(&key, &iv)
			.seal_inplace(&mut result, &[])
			.expect("Cannot seal response length.");
		result.put_slice(&tag);
	}
	// Encrypting response payload.
	{
		let response_buf_result = append_mut(&mut result, response_buf);

		let key = kdf::new_16(response_key, [AEAD_RESP_HEADER_KEY].iter().copied());
		let iv = kdf::new_12(response_iv, [AEAD_RESP_HEADER_IV].iter().copied());

		let tag = new_aead_encryptor(&key, &iv)
			.seal_inplace(response_buf_result, &[])
			.expect("Cannot seal response payload");
		result.put_slice(&tag);
	}
	result
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_aead_response() {
		let mut rng = rand::thread_rng();
		let response_key = rng.gen();
		let response_iv = rng.gen();

		// response with verification code of 123
		let response_buf = [123, 0, 0, 0];

		let mut result = seal_response(&response_buf, &response_key, &response_iv);
		let (mut length_slice, mut payload_slice) = result.split_at_mut(18);
		let len = open_len(&mut length_slice, &response_key, &response_iv).unwrap();
		assert_eq!(len + 16, payload_slice.len());
		let payload = open_payload(&mut payload_slice, &response_key, &response_iv).unwrap();
		assert_eq!(response_buf, payload);
	}
}
