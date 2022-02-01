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

#[cfg(all(feature = "__tls_rustls", feature = "__tls_openssl"))]
compile_error!("Cannot use rustls when OpenSSL is used as TLS library.");

#[cfg_attr(feature = "__tls_openssl", path = "openssl.rs")]
#[cfg_attr(feature = "__tls_rustls", path = "rustls.rs")]
mod internal;

pub use internal::{ClientStream, ServerStream, SslError};

use crate::protocol::SocksAddr;
use std::{borrow::Cow, io};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	#[error("empty alpns")]
	EmptyAlpns,
	#[error("alpn '{0:?}' too long")]
	AlpnTooLong(Vec<u8>),
	#[error("TLS error({0})")]
	SslError(#[from] SslError),
	#[error("{0}")]
	Other(Cow<'static, str>),
}

pub struct Acceptor(internal::Acceptor);

impl Acceptor {
	pub fn new<'a>(
		cert_file: &str,
		key_file: &str,
		alpns: impl IntoIterator<Item = &'a [u8]>,
	) -> Result<Self, ConfigError> {
		internal::Acceptor::new(cert_file, key_file, alpns).map(Acceptor)
	}

	pub async fn accept<RW>(&self, stream: RW) -> io::Result<ServerStream<RW>>
	where
		RW: AsyncRead + AsyncWrite + Unpin,
	{
		self.0.accept(stream).await
	}
}

pub struct Connector(internal::Connector);

impl Connector {
	pub fn new<'a>(
		alpns: impl IntoIterator<Item = &'a [u8]>,
		ca_file: Option<&str>,
	) -> Result<Self, ConfigError> {
		internal::Connector::new(alpns, ca_file).map(Connector)
	}

	pub async fn connect<RW>(&self, stream: RW, addr: &SocksAddr) -> io::Result<ClientStream<RW>>
	where
		RW: AsyncRead + AsyncWrite + Unpin,
	{
		self.0.connect(stream, addr).await
	}
}
