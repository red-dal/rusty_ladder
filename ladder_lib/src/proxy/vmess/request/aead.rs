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

use crate::{
	prelude::*,
	proxy::vmess::{
		aead_header::{auth_id, kdf, new_aead_decryptor, new_aead_encryptor},
		utils::Error,
	},
	utils::{
		append_mut, append_u16_mut,
		crypto::aead::{Decrypt, Encrypt},
	},
};

const VMESS_HEADER_KEY_LENGTH: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_HEADER_NONCE_LENGTH: &[u8] = b"VMess Header AEAD Nonce_Length";

const VMESS_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";

#[allow(dead_code)]
pub fn seal_request(request_buf: &[u8], cmd_key: &[u8; 16], time: i64) -> Vec<u8> {
	// Sealed request format:
	//
	// +---------+---------+---------+------+-------------+-------------+
	// | auth_id | enc_len | len_tag | rand | enc_payload | payload_tag |
	// +---------+---------+---------+------+-------------+-------------+
	// |   16B   |    2B   |   16B   |  8B  |      nB     |     16B     |
	// +---------+---------+---------+------+-------------+-------------+
	//
	// enc_len: encrypted length of the request_buf.
	// len_tag: tag of the encrypted length.
	//
	// rand: 8 bytes of random number.
	//
	// enc_payload: encrypted payload.
	// payload_tag: tag of the encrypted payload.
	//
	// Both length and payload is encrypted with AES-128-GCM.

	trace!("Sealing request with AEAD");
	let mut result = Vec::with_capacity(128);
	let mut rng = rand::thread_rng();

	let auth_id = auth_id::new(cmd_key, rng.gen(), time);
	// 8 bytes of random number
	let rand: [u8; 8] = rng.next_u64().to_ne_bytes();
	let header_len = u16::try_from(request_buf.len()).expect("request_buf too large");

	// Put auth_id.
	result.extend_from_slice(&auth_id);

	trace!(
		"VMess AEAD request auth_id: {:?}, header length: {}",
		auth_id,
		header_len
	);
	// Put length and length tag.
	{
		let result_length = append_u16_mut(&mut result, header_len);

		let payload_header_length_aead_key = kdf::new_16(
			cmd_key,
			[VMESS_HEADER_KEY_LENGTH, &auth_id, &rand].iter().copied(),
		);

		let payload_header_length_aead_nonce = kdf::new_12(
			cmd_key,
			[VMESS_HEADER_NONCE_LENGTH, &auth_id, &rand].iter().copied(),
		);

		// there should not be any error
		let tag = new_aead_encryptor(
			&payload_header_length_aead_key,
			&payload_header_length_aead_nonce,
		)
		.seal_inplace(result_length, auth_id.as_ref())
		.unwrap();
		result.extend(&tag);
	}

	// Put rand.
	result.extend(&rand);

	// Put payload and payload tag.
	{
		let result_payload = append_mut(&mut result, request_buf);

		let payload_header_aead_key =
			kdf::new_16(cmd_key, [VMESS_HEADER_KEY, &auth_id, &rand].iter().copied());

		let payload_header_aead_nonce = kdf::new_12(
			cmd_key,
			[VMESS_HEADER_NONCE, &auth_id, &rand].iter().copied(),
		);
		let tag = new_aead_encryptor(&payload_header_aead_key, &payload_header_aead_nonce)
			.seal_inplace(result_payload, auth_id.as_ref())
			.expect("Cannot seal VMess request");
		result.extend(&tag);
	}
	trace!("VMess request buffer len: {}", result.len());
	result
}

pub fn open_len(
	buf: &mut [u8],
	conn_nonce: &[u8],
	cmd_key: &[u8; 16],
	auth_id: &[u8; 16],
) -> Result<usize, Error> {
	debug_assert_eq!(buf.len(), 18);

	let payload_header_length_aead_key = kdf::new_16(
		cmd_key,
		[VMESS_HEADER_KEY_LENGTH, auth_id, conn_nonce]
			.iter()
			.copied(),
	);

	let payload_header_length_aead_nonce = kdf::new_12(
		cmd_key,
		[VMESS_HEADER_NONCE_LENGTH, auth_id, conn_nonce]
			.iter()
			.copied(),
	);

	let mut decryptor = new_aead_decryptor(
		&payload_header_length_aead_key,
		&payload_header_length_aead_nonce,
	);
	decryptor
		.open_inplace(buf, auth_id)
		.map_err(Error::new_crypto)?;
	let len = usize::from((&*buf).get_u16());
	Ok(len)
}

pub fn open_payload<'a>(
	buf: &'a mut [u8],
	nonce: &[u8],
	cmd_key: &[u8; 16],
	auth_id: &[u8; 16],
) -> Result<&'a [u8], Error> {
	debug_assert!(buf.len() > 16);
	let key = kdf::new_16(cmd_key, [VMESS_HEADER_KEY, auth_id, nonce].iter().copied());

	let iv = kdf::new_12(
		cmd_key,
		[VMESS_HEADER_NONCE, auth_id, nonce].iter().copied(),
	);
	let mut decryptor = new_aead_decryptor(&key, &iv);
	let buf = decryptor
		.open_inplace(buf, auth_id)
		.map_err(Error::new_crypto)?;
	Ok(buf)
}

#[cfg(test)]
mod tests {
	use super::super::{utils, write_request_to, Command, Request};
	use super::*;
	use crate::utils::timestamp_now;
	use std::convert::TryInto;
	use uuid::Uuid;

	#[test]
	fn test_aead_request() {
		let mut rng = rand::thread_rng();
		let payload_iv = rng.gen();
		let payload_key = rng.gen();
		let target_addr = SocketAddr::from_str("127.0.0.1:12345").unwrap().into();

		let mut request = Request::new(&payload_iv, &payload_key, target_addr, Command::Tcp);
		request.p = (rng.next_u32() % 16) as u8;
		request.v = rng.next_u32() as u8;

		let uuid = Uuid::from_str("1e562b2a-d1b3-41c0-8242-996e12b2a61a").unwrap();
		let time = timestamp_now();
		let cmd_key = utils::new_cmd_key(&uuid);

		let mut request_buf = Vec::with_capacity(256);
		write_request_to(&request, &mut request_buf);

		let mut buf = seal_request(&request_buf, &cmd_key, time);

		let (auth_id, buf) = buf.split_at_mut(16);
		let auth_id = &auth_id[..].try_into().unwrap();
		let (len_buf, tmp_buf) = buf.split_at_mut(18);
		let (conn_nonce, payload_buf) = tmp_buf.split_at_mut(8);

		let len = open_len(len_buf, conn_nonce, &cmd_key, auth_id).unwrap();
		assert_eq!(len + 16, payload_buf.len());

		let payload = open_payload(payload_buf, conn_nonce, &cmd_key, auth_id).unwrap();
		assert_eq!(payload, request_buf);
	}
}
