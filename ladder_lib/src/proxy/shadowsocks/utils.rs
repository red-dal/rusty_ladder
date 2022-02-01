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
	protocol::{outbound::Error as OutboundError, socks_addr::ReadError},
	utils::crypto::aead::{Algorithm, Key},
};
use bytes::Bytes;
use hkdf::Hkdf;
use md5::{digest::Digest, Md5};
use sha1::Sha1;

const INFO: &[u8] = b"ss-subkey";

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Shadowsocks error ({0})")]
	FailedCrypto(BoxStdErr),
	#[error("Shadowsocks error (duplicated salt {0:?})")]
	DuplicatedSalt(Box<[u8]>),
	#[error("Shadowsocks error ({0})")]
	FailedAddressParsing(ReadError),
	#[error("Shadowsocks error (datagram ({0} bytes) too small)")]
	DatagramTooSmall(usize),
	#[error("empty buffer")]
	EmptyBuffer,
}

impl From<ReadError> for Error {
	fn from(e: ReadError) -> Self {
		Error::FailedAddressParsing(e)
	}
}

impl From<Error> for OutboundError {
	#[inline]
	fn from(e: Error) -> Self {
		OutboundError::Protocol(e.into())
	}
}

pub fn password_to_key(key_len: usize, password: &str) -> Bytes {
	let digest_len = Md5::output_size();
	let mut result = Vec::with_capacity(std::cmp::max(key_len, digest_len) * 2);

	let mut m = None;
	let mut d = Md5::new();
	while result.len() < key_len {
		if let Some(ref rm) = m {
			d.update(rm);
		}
		d.update(password);
		let digest = d.finalize_reset();
		result.put(&*digest);

		m = Some(digest);
	}

	result.truncate(key_len);
	result.into()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub enum Method {
	#[cfg_attr(feature = "use_serde", serde(rename = "none"))]
	None,
	#[cfg_attr(feature = "use_serde", serde(rename = "aes-128-gcm"))]
	Aes128Gcm,
	#[cfg_attr(feature = "use_serde", serde(rename = "aes-256-gcm"))]
	Aes256Gcm,
	#[cfg_attr(feature = "use_serde", serde(rename = "chacha20-poly1305"))]
	Chacha20Poly1305,
}

impl Method {
	#[inline]
	#[must_use]
	pub fn new_from_str(s: &str) -> Option<Self> {
		Some(match s {
			"none" => Method::None,
			"aes-128-gcm" => Method::Aes128Gcm,
			"aes-256-gcm" => Method::Aes256Gcm,
			"chacha20-poly1305" => Method::Chacha20Poly1305,
			_ => return None,
		})
	}
}

pub fn method_to_algo(method: Method) -> Option<Algorithm> {
	Some(match method {
		Method::None => return None,
		Method::Aes128Gcm => Algorithm::Aes128Gcm,
		Method::Aes256Gcm => Algorithm::Aes256Gcm,
		Method::Chacha20Poly1305 => Algorithm::ChaCha20Poly1305,
	})
}

pub fn key_to_session_key(key: &[u8], salt: &[u8], algo: Algorithm) -> Key {
	let key_len = salt_len(algo);
	debug_assert_eq!(salt.len(), key_len);
	let h = Hkdf::<Sha1>::new(Some(salt), key);
	// Fill output
	match algo {
		Algorithm::Aes128Gcm => {
			let mut okm = [0_u8; 16];
			h.expand(INFO, &mut okm)
				.expect("invalid key length for hkdf expending");
			Key::Aes128Gcm(okm)
		}
		Algorithm::Aes256Gcm => {
			let mut okm = [0_u8; 32];
			h.expand(INFO, &mut okm)
				.expect("invalid key length for hkdf expending");
			Key::Aes256Gcm(okm)
		}
		Algorithm::ChaCha20Poly1305 => {
			let mut okm = [0_u8; 32];
			h.expand(INFO, &mut okm)
				.expect("invalid key length for hkdf expending");
			Key::ChaCha20Poly1305(okm)
		}
	}
}

#[inline]
pub fn salt_len(algo: Algorithm) -> usize {
	algo.key_size().get().into()
}

#[cfg(feature = "parse-url")]
pub(super) fn get_method_password(url: &url::Url) -> Result<(Method, String), BoxStdErr> {
	// Format:
	// ss://userinfo@host:port
	//
	// where userinfo is base64(method ":" password)
	// Currently plugin is not supported so path must be empty.
	//
	// Read more at https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html

	if url.password().is_some() {
		return Err("Shadowsocks URL should not have a password".into());
	}
	let userinfo = url.username();
	let userinfo_str = String::from_utf8(base64::decode(userinfo)?)?;
	let (method_str, password) = userinfo_str.split_once(':').ok_or("invalid userinfo")?;
	let method =
		Method::new_from_str(method_str).ok_or_else(|| format!("unknown method '{}'", method_str))?;
	Ok((method, password.into()))
}