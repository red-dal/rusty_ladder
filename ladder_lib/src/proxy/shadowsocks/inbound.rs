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

use super::{method_to_algo, tcp, utils::salt_len, Error, Method, PROTOCOL_NAME};
use crate::{
	prelude::*,
	protocol::{
		inbound::{AcceptError, AcceptResult, PlainHandshakeHandler, SessionInfo, TcpAcceptor},
		socks_addr::ReadError,
		AsyncReadWrite, BufBytesStream, CompositeBytesStream, GetProtocolName,
	},
	utils::crypto::aead::Algorithm,
};
use bytes::Bytes;
use rand::thread_rng;

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	pub method: Method,
	pub password: String,
}

impl SettingsBuilder {
	/// Creates a Shadowsocks inbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(Settings::new(&self.password, self.method))
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// ss://userinfo@bind_addr:bind_port
	/// ```
	/// `userinfo` is `base64("method:password")`,
	///
	/// where `method` must be one of
	/// "none", "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305".
	///
	/// Read more at <https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html>
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;
		let (method, password) = super::utils::get_method_password(url)?;
		Ok(Self { method, password })
	}
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct CryptoSettings {
	password: Bytes,
	algo: Algorithm,
}

pub struct Settings {
	crypto: Option<CryptoSettings>,
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpAcceptor for Settings {
	#[inline]
	async fn accept_tcp<'a>(
		&'a self,
		mut stream: Box<dyn AsyncReadWrite>,
		_info: SessionInfo,
	) -> Result<AcceptResult<'a>, AcceptError> {
		trace!("Accepting shadowsocks inbound");
		if let Some(s) = &self.crypto {
			// with encryption
			trace!("Reading shadowsocks salt");
			// very unlikely to generate a used salt
			let local_salt = {
				let mut salt = vec![0_u8; salt_len(s.algo)];
				thread_rng().fill_bytes(&mut salt);
				salt
			};
			let (mut crypt_read, crypt_write) =
				tcp::new_crypt_stream(stream, s.algo, s.password.clone(), local_salt);
			trace!("Reading shadowsocks target addr");
			let addr = read_request(&mut crypt_read).await;
			let addr = match addr {
				Ok(a) => a,
				Err(ReadError::Io(e)) => {
					return Err(e.into());
				}
				Err(e) => {
					let raw_stream = CompositeBytesStream {
						r: crypt_read.r,
						w: crypt_write.w,
					};
					return invalid_request(Box::new(raw_stream), e);
				}
			};
			trace!("Shadowsocks target address: {}", addr);
			let crypt_stream = BufBytesStream {
				r: Box::new(crypt_read),
				w: Box::new(crypt_write),
			};

			Ok(AcceptResult::Tcp(
				Box::new(PlainHandshakeHandler(crypt_stream)),
				addr,
			))
		} else {
			// without encryption
			trace!("Reading shadowsocks request");
			let addr = read_request(&mut stream).await;
			let addr = match addr {
				Ok(a) => a,
				Err(ReadError::Io(e)) => {
					return Err(e.into());
				}
				Err(e) => {
					return invalid_request(stream, e);
				}
			};
			trace!("Shadowsocks target address: {}", addr);

			Ok(AcceptResult::Tcp(
				Box::new(PlainHandshakeHandler(BufBytesStream::from(stream))),
				addr,
			))
		}
	}
}

impl Settings {
	#[must_use]
	pub fn new(password: &str, method: Method) -> Self {
		let crypt_settings = method_to_algo(method).map(|algo| {
			let password = super::password_to_key(salt_len(algo), password);
			CryptoSettings { password, algo }
		});

		Settings {
			crypto: crypt_settings,
		}
	}
}

async fn read_request<R>(reader: &mut R) -> Result<SocksAddr, ReadError>
where
	R: AsyncRead + Unpin,
{
	let addr: SocksAddr = SocksAddr::async_read_from(reader).await?;
	Ok(addr)
}

#[inline]
fn invalid_request<T>(
	stream: Box<dyn AsyncReadWrite>,
	e: impl Into<Error>,
) -> Result<T, AcceptError> {
	Err(AcceptError::new_silent_drop(stream, e.into()))
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use super::{Method, SettingsBuilder};
		use std::str::FromStr;
		use url::Url;

		let data = [(
			"ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1",
			SettingsBuilder {
				method: Method::Aes128Gcm,
				password: "test".to_owned(),
			},
		)];

		for (url, expected) in data {
			let url = Url::from_str(url).unwrap();
			let output = SettingsBuilder::parse_url(&url).unwrap();
			assert_eq!(expected, output);
		}
	}
}
