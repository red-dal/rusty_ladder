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

/*!
Shadowsocks TCP functions. Only AEAD encryption is supported.

### AEAD

An AEAD encrypted TCP stream stars with a randomly generated salt
used to derive the session key, follow by any number of payloads.

Each payload has the following structure:
```not_rust
+------------------+------------+-------------+----------+
|    encrypted     |    length  |  encrypted  |  payload |
|  payload length  |     tag    |   payload   |    tag   |
+------------------+------------+-------------+----------+
|     2 bytes      |  16 bytes  |  n bytes    | 16 bytes |
+------------------+------------+-------------+----------+
```

To initiate a Shadowsocks connection, client must first send the target address
in [SOCKS5 address format] ( use [`SocksAddr::write_to`] to serialize ) as one
of the payload.

For better obfuscation, both client and server should send it
with next payload, which is usually the handshake of the proxied traffic.

So the first packet should look like
```not_rust
+-------------------+------------------+---------------+
|      salt         |  target address  |     next      |
|                   |     payload      |    payload    |
+-------------------+------------------+---------------+
|  algo.key_len()   |     various      |    various    |
|     bytes         |      bytes       |     bytes     |
+-------------------+------------------+---------------+
```

### Plain

For non-encrypted stream, client need to send target address and payloads to
server but without salt and any encryption on payloads.

Beware that in plain mode there is no authentication or encryption,
and should not be used in unsecured network.

[SOCKS5 address format]: https://tools.ietf.org/html/rfc1928#section-5
*/

use super::{key_to_session_key, utils::salt_len, Error};
use crate::{
	non_zeros,
	prelude::*,
	protocol::{BoxRead, BoxWrite, BytesStream},
	utils::{
		append_mut, append_u16_mut,
		codec::{self, FrameReader, FrameWriter},
		crypto::aead::{
			self,
			nonce::{CounterSequence, EMPTY as EMPTY_NONCE},
			Algorithm, Decrypt, Encrypt,
		},
	},
};
use bytes::Bytes;
use std::num::NonZeroU16;

const MAX_PAYLOAD_SIZE: u16 = 16 * 1024 - 1;

#[inline]
fn default_write_nonce() -> CounterSequence {
	CounterSequence::new(EMPTY_NONCE)
}

#[inline]
fn default_read_nonce() -> CounterSequence {
	CounterSequence::new(EMPTY_NONCE)
}

pub type CryptFrameReader = FrameReader<Decoder, BoxRead>;
pub type CryptFrameWriter = FrameWriter<Encoder, BoxWrite>;

pub fn new_crypt_stream(
	stream: BytesStream,
	algo: Algorithm,
	password: Bytes,
	local_salt: Vec<u8>,
) -> (CryptFrameReader, CryptFrameWriter) {
	let w = FrameWriter::new(
		MAX_PAYLOAD_SIZE.into(),
		Encoder::new(algo, default_write_nonce(), &password, local_salt),
		stream.w,
	);
	let r = FrameReader::new(Decoder::new(algo, password), stream.r);
	(r, w)
}

enum ReadState {
	Salt {
		key: Bytes,
	},
	Decrypt {
		dec: Box<aead::Decryptor<CounterSequence>>,
		state: DecodeState,
	},
}

enum DecodeState {
	Length,
	Payload(NonZeroU16),
}

pub struct Decoder {
	state: ReadState,
	algo: Algorithm,
}

impl Decoder {
	pub fn new(algo: Algorithm, key: Bytes) -> Self {
		Self {
			algo,
			state: ReadState::Salt { key },
		}
	}
}

impl codec::Decode for Decoder {
	fn expected_len(&self) -> Option<std::num::NonZeroUsize> {
		match &self.state {
			// Obviously larger than 0.
			ReadState::Salt { key: _ } => Some(self.algo.key_size().into()),
			ReadState::Decrypt { dec: _, state } => match state {
				// Length part is always ( 2 + TAG_LEN (16 bytes) = 18 bytes ).
				DecodeState::Length => Some(non_zeros::U8_18.into()),
				DecodeState::Payload(len) => Some(non_zeros::add_u8_u16(aead::TAG_LEN_N, *len)),
			},
		}
	}

	fn decode_inplace(&mut self, buf: &mut Vec<u8>) -> Result<bool, BoxStdErr> {
		if buf.is_empty() {
			// Handle EOF.
			// Only in Decrypt Length state EOF is acceptable.
			return match &self.state {
				ReadState::Salt { key: _ } => Err("EOF while reading Shadowsocks salt".into()),
				ReadState::Decrypt { dec: _, state } => match &state {
					DecodeState::Length => Ok(true),
					DecodeState::Payload(_) => Err("EOF while reading Shadowsocks payload".into()),
				},
			};
		}
		// A salt must be read from remote to build a session key before actually decoding payloads.
		// State graph:
		//                +----------------+   Needs more n bytes     +-----------------+
		// +------+       |                |    return Ok(false);     |                 |
		// |      |       |                +------------------------->|                 |
		// | Salt +------>| Decrypt_Length |                          | Decrypt_Payload |
		// |      |       |                |<-------------------------+                 |
		// +------+       |                |    return Ok(true);      |                 |
		//                +----------------+   Expects 18 bytes       +-----------------+

		match &mut self.state {
			ReadState::Salt { ref key } => {
				trace!("Reading Shadowsocks salt...");

				let salt = buf.as_slice();
				assert_eq!(salt_len(self.algo) as usize, salt.len());

				let session_key = key_to_session_key(key, salt, self.algo);
				// Generate AEAD decryptor with default nonce.
				let dec = aead::Decryptor::new_decryptor(session_key, default_read_nonce())
					.map_err(Error::FailedCrypto)?;
				self.state = ReadState::Decrypt {
					dec: Box::new(dec),
					state: DecodeState::Length,
				};
				// Proceed to read payload.
				Ok(false)
			}
			ReadState::Decrypt { dec, state } => {
				match state {
					DecodeState::Length => {
						trace!("Reading Shadowsocks payload length...");

						assert_eq!(buf.len(), 2 + aead::TAG_LEN);
						if let Err(e) = dec.open_inplace(buf, &[]) {
							return Err(Error::FailedCrypto(
								format!(
									"Cannot decrypt Shadowsocks length data of {} bytes {:?} ({})",
									buf.len(),
									buf,
									e
								)
								.into(),
							)
							.into());
						};
						if let Some(len) = NonZeroU16::new(buf.as_slice().get_u16()) {
							// Change state and tell reader
							// more bytes are needed.
							*state = DecodeState::Payload(len);
							trace!("Done reading length ({}), going to decode payload.", len);
							Ok(false)
						} else {
							Err(Error::EmptyBuffer.into())
						}
					}
					DecodeState::Payload(ref len) => {
						trace!("Reading Shadowsocks payload ({} bytes)...", len);

						let len = usize::from(len.get());
						assert_eq!(buf.len(), len + aead::TAG_LEN);
						if let Err(e) = dec.open_inplace(buf, &[]) {
							return Err(Error::FailedCrypto(
								format!(
									"cannot decrypt shadowsocks payload data of {} bytes ({})",
									buf.len(),
									e
								)
								.into(),
							)
							.into());
						};
						buf.truncate(len);
						*state = DecodeState::Length;
						trace!("Done reading Shadowsocks payload (now {} bytes), going to decode length.", buf.len());
						Ok(true)
					}
				}
			}
		}
	}
}

type Encryptor = aead::Encryptor<CounterSequence>;

pub struct Encoder {
	pub lazy_buf: Vec<u8>,
	enc: Encryptor,
}

impl Encoder {
	pub fn new(algo: Algorithm, nonce: CounterSequence, key: &[u8], local_salt: Vec<u8>) -> Self {
		let session_key = key_to_session_key(key, &local_salt, algo);
		Self {
			lazy_buf: local_salt,
			enc: aead::Encryptor::new_encryptor(session_key, nonce)
				.expect("cannot create Shadowsocks Encoder, possibly invalid key length"),
		}
	}

	#[allow(dead_code)]
	pub fn encode_into_lazy(&mut self, src: &[u8]) -> Result<(), BoxStdErr> {
		Self::priv_encode(&mut self.enc, src, &mut self.lazy_buf)
	}

	fn priv_encode(enc: &mut Encryptor, src: &[u8], buf: &mut Vec<u8>) -> Result<(), BoxStdErr> {
		let src_len = u16::try_from(src.len())
			.ok()
			.filter(|len| *len <= MAX_PAYLOAD_SIZE)
			.ok_or_else(|| {
				format!(
					"payload length too large ({}), must be smaller than {}",
					src.len(),
					MAX_PAYLOAD_SIZE
				)
			})?;

		if src_len == 0 {
			return Err("payload length cannot be zero".into());
		}

		// Reserve for src.
		// DO NOT clean up buffer.
		{
			let mut buf_len = 2 + aead::TAG_LEN;
			buf_len += src.len() + aead::TAG_LEN;
			buf.reserve(buf_len);
		}
		{
			// Payload length.
			// 2 + TAG_LEN bytes.
			let len_buf = append_u16_mut(buf, src_len);
			let tag = enc.seal_inplace(len_buf, &[])?;
			buf.put_slice(&tag);
		}
		{
			// Payload.
			// src.len() + TAG_LEN bytes.
			let payload_buf = append_mut(buf, src);
			let tag = enc.seal_inplace(payload_buf, &[])?;
			buf.put_slice(&tag);
		}
		Ok(())
	}
}

impl codec::Encode for Encoder {
	fn encode_into(&mut self, src: &[u8], buf: &mut Vec<u8>) -> Result<(), BoxStdErr> {
		buf.clear();

		if !self.lazy_buf.is_empty() {
			buf.put_slice(&self.lazy_buf);
			// Release memory.
			self.lazy_buf = Vec::new();
		}

		Self::priv_encode(&mut self.enc, src, buf)?;
		trace!(
			"Encoding src ({} bytes) into buf ({} bytes)",
			src.len(),
			buf.len()
		);
		Ok(())
	}
}
