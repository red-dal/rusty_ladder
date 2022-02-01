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

use super::ConfigError;
use crate::{prelude::*, protocol::AsyncReadWrite};
use openssl::ssl::{self, Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslRef};
use std::io;
use tokio_openssl::SslStream;

pub use openssl::error::ErrorStack as SslError;

pub type ServerStream<RW> = SslStream<RW>;
pub type ClientStream<RW> = SslStream<RW>;

fn select_alpn_h2<'a>(_ssl: &mut SslRef, client: &'a [u8]) -> &'a [u8] {
	trace!("alpn client: {:?}", client);
	if let Some(client) = ssl::select_next_proto(b"\x02h2", client) {
		return client;
	}
	// Return first
	let (len, data) = client.split_at(1);
	let len = len[0] as usize;
	&data[..len]
}

pub struct Acceptor(SslAcceptor);

impl Acceptor {
	pub fn new<'a>(
		cert_file: &str,
		key_file: &str,
		alpns: impl IntoIterator<Item = &'a [u8]>,
	) -> Result<Self, ConfigError> {
		let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls_server())?;
		// Set alpn protocols.
		let protocols = make_alpn_protocols(alpns)?;
		if !protocols.is_empty() {
			builder.set_alpn_select_callback(|ssl, client| Ok(select_alpn_h2(ssl, client)));
		}

		// Set cert_file and key_file.
		builder.set_certificate_chain_file(cert_file)?;
		builder.set_private_key_file(key_file, SslFiletype::PEM)?;
		builder.check_private_key()?;

		Ok(Self(builder.build()))
	}

	pub async fn accept<RW>(&self, stream: RW) -> io::Result<ServerStream<RW>>
	where
		RW: AsyncRead + AsyncWrite + Unpin,
	{
		let ssl = Ssl::new(self.0.context())?;
		let mut stream = SslStream::new(ssl, stream)?;
		Pin::new(&mut stream)
			.accept()
			.await
			.map_err(make_io_error)?;
		Ok(stream)
	}
}

pub struct Connector(SslConnector);

impl Connector {
	pub fn new<'a>(
		alpns: impl IntoIterator<Item = &'a [u8]>,
		ca_file: Option<&str>,
	) -> Result<Self, ConfigError> {
		let mut builder = SslConnector::builder(SslMethod::tls_client())?;

		let protocols = make_alpn_protocols(alpns)?;
		if !protocols.is_empty() {
			builder.set_alpn_protos(&protocols)?;
		}
		if let Some(ca_file) = ca_file {
			builder.set_ca_file(ca_file)?;
		}

		Ok(Self(builder.build()))
	}

	pub async fn connect<RW>(&self, stream: RW, addr: &SocksAddr) -> io::Result<ClientStream<RW>>
	where
		RW: AsyncRead + AsyncWrite + Unpin,
	{
		let name = addr.dest.to_str();
		trace!("OpenSSL connect to {}", name);
		let ssl = self.0.configure()?.into_ssl(&name)?;
		let mut stream = SslStream::new(ssl, stream)?;
		Pin::new(&mut stream)
			.connect()
			.await
			.map_err(make_io_error)?;
		Ok(stream)
	}
}

fn make_alpn_protocols<'a>(
	alpns: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, ConfigError> {
	let mut protocols = Vec::<u8>::new();
	for alpn in alpns {
		debug_assert!(!alpn.is_empty());
		debug_assert!(alpn.len() < 256);

		if alpn.is_empty() {
			return Err(ConfigError::EmptyAlpns);
		}
		let len = u8::try_from(alpn.len()).map_err(|_| ConfigError::AlpnTooLong(alpn.into()))?;
		protocols.put_u8(len);
		protocols.put_slice(alpn);
	}
	Ok(protocols)
}

#[inline]
fn make_io_error(err: openssl::ssl::Error) -> io::Error {
	match err.into_io_error() {
		Ok(io_err) => io_err,
		Err(err) => io::Error::new(io::ErrorKind::Other, err),
	}
}

impl<IO: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncReadWrite for SslStream<IO> {
	fn split(self: Box<Self>) -> (crate::protocol::BoxRead, crate::protocol::BoxWrite) {
		let (r, w) = tokio::io::split(*self);
		(Box::new(r), Box::new(w))
	}
}

impl<IO> From<SslStream<IO>> for Box<dyn AsyncReadWrite>
where
	IO: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	fn from(stream: SslStream<IO>) -> Self {
		Box::new(stream)
	}
}
