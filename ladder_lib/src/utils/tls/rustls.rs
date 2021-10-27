use super::ConfigError;
use crate::protocol::{ProxyStream, SocksAddr, SocksDestination};
use std::{io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls;

pub type ClientStream<RW> = tokio_rustls::client::TlsStream<RW>;
pub type ServerStream<RW> = tokio_rustls::server::TlsStream<RW>;

#[derive(thiserror::Error, Debug)]
pub enum SslError {
	#[error("Cannot read file {1} ({0})")]
	CannotReadFile(io::Error, String),
	#[error("Cannot parse certificate file")]
	CannotParseCertificateFile,
	#[error("Cannot parse private key file")]
	CannotParsePrivateKeyFile,
	#[error("Webpki error ({0})")]
	WebPkiError(webpki::Error),
	#[error("TLSError ({0})")]
	Other(rustls::TLSError),
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
		let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
		{
			let cert_file = std::fs::File::open(cert_file)
				.map_err(|e| SslError::CannotReadFile(e, cert_file.to_string()))?;
			let key_file = std::fs::File::open(key_file)
				.map_err(|e| SslError::CannotReadFile(e, key_file.to_string()))?;
			let cert = rustls::internal::pemfile::certs(&mut io::BufReader::new(cert_file))
				.map_err(|_| SslError::CannotParseCertificateFile)?;
			let key =
				rustls::internal::pemfile::pkcs8_private_keys(&mut io::BufReader::new(key_file))
					.map_err(|_| SslError::CannotParsePrivateKeyFile)?;
			let key = key.into_iter().next().ok_or(ConfigError::EmptyKeyFile)?;
			config.set_single_cert(cert, key).map_err(SslError::Other)?;
			// config
			// 	.set_single_cert_with_ocsp_and_sct(cert, key, vec![], vec![])
			// 	.map_err(SslError::Other)?;
		}
		let alpns = alpns.into_iter().map(|a| a.to_vec()).collect::<Vec<_>>();
		config.alpn_protocols = alpns;
		let config = Arc::new(config);
		Ok(Acceptor {
			inner: config.into(),
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
		ca_file: &str,
	) -> Result<Self, ConfigError> {
		let mut config = rustls::ClientConfig::new();
		if ca_file.is_empty() {
			config
				.root_store
				.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
		} else {
			let ca_file = std::fs::File::open(ca_file)
				.map_err(|e| SslError::CannotReadFile(e, ca_file.to_string()))?;
			let (_added, _unsuitable) = config
				.root_store
				.add_pem_file(&mut std::io::BufReader::new(ca_file))
				.map_err(|_| SslError::CannotParseCertificateFile)?;
		}
		let alpns = alpns.into_iter().map(|a| a.to_vec()).collect::<Vec<_>>();
		config.alpn_protocols = alpns;
		Ok(Self {
			inner: Arc::new(config).into(),
		})
	}

	pub async fn connect<RW>(&self, stream: RW, addr: &SocksAddr) -> io::Result<ClientStream<RW>>
	where
		RW: AsyncRead + AsyncWrite + Unpin,
	{
		let name = match &addr.dest {
			SocksDestination::Name(name) => webpki::DNSNameRef::try_from_ascii(name.as_bytes())
				.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
			SocksDestination::Ip(_) => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"Rustls does not support IP as target",
				))
			}
		};
		self.inner.connect(name, stream).await
	}
}

impl<RW> From<ClientStream<RW>> for ProxyStream
where
	RW: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	fn from(s: ClientStream<RW>) -> Self {
		let (r, w) = tokio::io::split(s);
		ProxyStream::new(Box::new(r), Box::new(w))
	}
}

impl<RW> From<ServerStream<RW>> for ProxyStream
where
	RW: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	fn from(s: ServerStream<RW>) -> Self {
		let (r, w) = tokio::io::split(s);
		ProxyStream::new(Box::new(r), Box::new(w))
	}
}
