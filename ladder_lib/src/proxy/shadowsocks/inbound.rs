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

use super::{method_to_algo, tcp, utils::salt_len, Error, Method};
use crate::{
	prelude::*,
	protocol::{
		inbound::{AcceptError, AcceptResult, PlainHandshakeHandler, TcpAcceptor},
		socks_addr::ReadError,
		AsyncReadWrite, BytesStream, GetProtocolName,
	},
	transport,
	utils::crypto::aead::Algorithm,
};
use bytes::Bytes;
use rand::thread_rng;

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	pub method: Method,
	pub password: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: transport::inbound::SettingsBuilder,
}

impl SettingsBuilder {
	/// Creates a Shadowsocks inbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(Settings::new(
			&self.password,
			self.method,
			self.transport.build()?,
		))
	}
}

struct CryptoSettings {
	password: Bytes,
	algo: Algorithm,
}

pub struct Settings {
	crypto: Option<CryptoSettings>,
	transport: transport::inbound::Settings,
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		super::PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpAcceptor for Settings {
	#[inline]
	async fn accept_tcp<'a>(
		&'a self,
		stream: BytesStream,
	) -> Result<AcceptResult<'a>, AcceptError> {
		trace!("Accepting shadowsocks inbound");
		let mut stream = self.transport.accept(stream).await?;

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
					return invalid_request(
						BytesStream::new(Box::new(crypt_read), Box::new(crypt_write)),
						e,
					);
				}
			};
			trace!("Shadowsocks target address: {}", addr);
			let crypt_stream = BytesStream::new(Box::new(crypt_read), Box::new(crypt_write));

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
				Box::new(PlainHandshakeHandler(stream)),
				addr,
			))
		}
	}
}

impl Settings {
	#[must_use]
	pub fn new(password: &str, method: Method, transport: transport::inbound::Settings) -> Self {
		let crypt_settings = method_to_algo(method).map(|algo| {
			let password = super::password_to_key(salt_len(algo), password);
			CryptoSettings { password, algo }
		});

		Settings {
			crypto: crypt_settings,
			transport,
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
	stream: impl 'static + AsyncReadWrite,
	e: impl Into<Error>,
) -> Result<T, AcceptError> {
	Err(AcceptError::new_protocol(Box::new(stream), e.into()))
}
