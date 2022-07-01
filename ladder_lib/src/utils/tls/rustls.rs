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
use crate::protocol::{AsyncReadWrite, SocksAddr, SocksDestination, self};
use std::{convert::TryFrom, io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{self, ServerName};

pub type ClientStream<RW> = tokio_rustls::client::TlsStream<RW>;
pub type ServerStream<RW> = tokio_rustls::server::TlsStream<RW>;

#[derive(thiserror::Error, Debug)]
pub enum SslError {
	#[error("IO error {1} ({0})")]
	Io(io::Error, String),
	#[error("file '{0}' contains no cert")]
	MissingCert(String),
	#[error("file '{0}' contains no key")]
	MissingKey(String),
	#[error("cannot read native certs ({0})")]
	NativeCerts(io::Error),
	#[error("{0}")]
	RootCert(webpki::Error),
	#[error("TLS error ({0})")]
	Rustls(rustls::Error),
}

pub struct Acceptor {
	inner: tokio_rustls::TlsAcceptor,
}

impl Acceptor {
	pub fn new<'a>(
		cert_file: &str,
		key_file: &str,
		alpns: impl IntoIterator<Item = &'a [u8]>,
	) -> Result<Self, ConfigError> {
		let certs = {
			let f = std::fs::File::open(cert_file)
				.map_err(|e| SslError::Io(e, cert_file.to_string()))?;
			rustls_pemfile::certs(&mut io::BufReader::new(f))
				.map_err(|e| SslError::Io(e, cert_file.into()))?
				.into_iter()
				.map(rustls::Certificate)
				.collect::<Vec<_>>()
		};
		if certs.is_empty() {
			return Err(SslError::MissingCert(cert_file.into()).into());
		}
		let key = {
			let f =
				std::fs::File::open(key_file).map_err(|e| SslError::Io(e, key_file.to_string()))?;
			rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(f))
				.map_err(|e| SslError::Io(e, key_file.into()))?
				.into_iter()
				.map(rustls::PrivateKey)
				.next()
				.ok_or_else(|| SslError::MissingKey(key_file.into()))?
		};
		let mut config = rustls::ServerConfig::builder()
			.with_safe_defaults()
			.with_no_client_auth()
			.with_single_cert(certs, key)
			.map_err(SslError::Rustls)?;
		let alpns: Vec<Vec<u8>> = alpns.into_iter().map(Vec::from).collect();
		if !alpns.is_empty() {
			config.alpn_protocols = alpns;
		}

		Ok(Acceptor {
			inner: Arc::new(config).into(),
		})
	}

	pub async fn accept<RW>(&self, stream: RW) -> io::Result<ServerStream<RW>>
	where
		RW: AsyncRead + AsyncWrite + Unpin,
	{
		self.inner.accept(stream).await
	}
}

pub struct Connector {
	inner: tokio_rustls::TlsConnector,
}

impl Connector {
	pub fn new<'a>(
		alpns: impl IntoIterator<Item = &'a [u8]>,
		ca_file: Option<&str>,
	) -> Result<Self, ConfigError> {
		let mut roots = rustls::RootCertStore::empty();
		let roots = if let Some(ca_file) = ca_file {
			let f = std::fs::File::open(ca_file).map_err(|e| SslError::Io(e, ca_file.into()))?;
			let certs = rustls_pemfile::certs(&mut io::BufReader::new(f))
				.map_err(|e| ConfigError::CannotReadCertFile(ca_file.into(), e))?;
			for item in certs {
				roots
					.add(&rustls::Certificate(item))
					.map_err(SslError::RootCert)?;
			}
			roots
		} else {
			let native_certs =
				rustls_native_certs::load_native_certs().map_err(SslError::NativeCerts)?;
			for cert in native_certs {
				roots
					.add(&rustls::Certificate(cert.0))
					.map_err(SslError::RootCert)?;
			}
			roots
		};

		let roots = roots;
		// Make config
		let mut config = rustls::ClientConfig::builder()
			.with_safe_defaults()
			.with_root_certificates(roots)
			.with_no_client_auth();
		let alpns: Vec<Vec<u8>> = alpns.into_iter().map(Into::into).collect();
		if !alpns.is_empty() {
			config.alpn_protocols = alpns;
		}
		Ok(Self {
			inner: Arc::new(config).into(),
		})
	}

	pub async fn connect<RW>(&self, stream: RW, addr: &SocksAddr) -> io::Result<ClientStream<RW>>
	where
		RW: AsyncRead + AsyncWrite + Unpin,
	{
		let name = match &addr.dest {
			SocksDestination::Name(name) => ServerName::try_from(name.as_str()).map_err(|e| {
				io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("invalid server name '{}' ({})", name, e),
				)
			})?,
			SocksDestination::Ip(ip) => ServerName::IpAddress(*ip),
		};
		self.inner.connect(name, stream).await
	}
}

impl<IO: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncReadWrite
	for ClientStream<IO>
{
	fn split(self: Box<Self>) -> (protocol::BoxRead, protocol::BoxWrite) {
		let (r, w) = tokio::io::split(*self);
		(Box::new(r), Box::new(w))
	}
}

impl<IO: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncReadWrite
	for ServerStream<IO>
{
	fn split(self: Box<Self>) -> (protocol::BoxRead, protocol::BoxWrite) {
		let (r, w) = tokio::io::split(*self);
		(Box::new(r), Box::new(w))
	}
}

impl<IO> From<ServerStream<IO>> for Box<dyn AsyncReadWrite>
where
	IO: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	fn from(stream: ServerStream<IO>) -> Self {
		Box::new(stream)
	}
}

impl<IO> From<ClientStream<IO>> for Box<dyn AsyncReadWrite>
where
	IO: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	fn from(stream: ClientStream<IO>) -> Self {
		Box::new(stream)
	}
}
