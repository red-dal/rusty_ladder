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

use http::Uri;

use super::tls;
use crate::{
	prelude::*,
	protocol::{
		socks_addr::{DomainName, ReadError},
		AsyncReadWrite, DisplayInfo, ProxyContext,
	},
	utils::websocket::{self, Stream as WsStream},
};
use std::{collections::HashMap, fmt::Write, io};

pub type PlainStream<IO> = WsStream<IO>;
pub type SecureClientStream<IO> = WsStream<tls::ClientStream<IO>>;
pub type SecureServerStream<IO> = WsStream<tls::ServerStream<IO>>;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
	#[error("header name '{0}' is invalid ({1})")]
	InvalidHeaderName(String, http::header::InvalidHeaderName),
	#[error("header value '{0}' is invalid ({1})")]
	InvalidHeaderValue(String, http::header::InvalidHeaderValue),
	#[error("invalid host ({0})")]
	InvalidHost(ReadError),
	#[error("tls ({0})")]
	Tls(#[from] crate::utils::tls::ConfigError),
	#[error("non-empty path '{0}' does not start with '/'")]
	PathNotStartsWithSlash(String),
}

// -------------------------------------------
//                ClientStream
// -------------------------------------------

// Use box because SecureClientStream is too big
pub enum ClientStream<IO: AsyncRead + AsyncWrite + Unpin> {
	Raw(Box<PlainStream<IO>>),
	Tls(Box<SecureClientStream<IO>>),
}

impl<IO> AsyncRead for ClientStream<IO>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<io::Result<()>> {
		match self.get_mut() {
			Self::Raw(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
			Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
		}
	}
}

impl<IO> AsyncWrite for ClientStream<IO>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize, io::Error>> {
		match self.get_mut() {
			Self::Raw(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
			Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
		}
	}

	fn poll_flush(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), io::Error>> {
		match self.get_mut() {
			Self::Raw(s) => Pin::new(s.as_mut()).poll_flush(cx),
			Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
		}
	}

	fn poll_shutdown(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), io::Error>> {
		match self.get_mut() {
			Self::Raw(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
			Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
		}
	}
}

impl<IO> AsyncReadWrite for ClientStream<IO>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn split(self: Box<Self>) -> (crate::protocol::BoxRead, crate::protocol::BoxWrite) {
		match *self {
			Self::Raw(stream) => stream.split(),
			Self::Tls(stream) => stream.split(),
		}
	}
}

impl<IO> From<ClientStream<IO>> for Box<dyn AsyncReadWrite>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn from(stream: ClientStream<IO>) -> Self {
		match stream {
			ClientStream::Raw(stream) => stream,
			ClientStream::Tls(stream) => stream,
		}
	}
}

// -------------------------------------------
//                ServerStream
// -------------------------------------------

pub enum ServerStream<IO: AsyncRead + AsyncWrite + Unpin> {
	Raw(Box<PlainStream<IO>>),
	Tls(Box<SecureServerStream<IO>>),
}

impl<IO> AsyncRead for ServerStream<IO>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<io::Result<()>> {
		match self.get_mut() {
			ServerStream::Raw(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
			ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
		}
	}
}

impl<IO> AsyncWrite for ServerStream<IO>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize, io::Error>> {
		match self.get_mut() {
			ServerStream::Raw(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
			ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
		}
	}

	fn poll_flush(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), io::Error>> {
		match self.get_mut() {
			ServerStream::Raw(s) => Pin::new(s.as_mut()).poll_flush(cx),
			ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
		}
	}

	fn poll_shutdown(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), io::Error>> {
		match self.get_mut() {
			ServerStream::Raw(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
			ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
		}
	}
}

impl<IO> AsyncReadWrite for ServerStream<IO>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn split(self: Box<Self>) -> (crate::protocol::BoxRead, crate::protocol::BoxWrite) {
		match *self {
			ServerStream::Raw(stream) => {
				let (r, w) = tokio::io::split(*stream);
				(Box::new(r), Box::new(w))
			}
			ServerStream::Tls(stream) => {
				let (r, w) = tokio::io::split(*stream);
				(Box::new(r), Box::new(w))
			}
		}
	}
}

impl<IO> From<ServerStream<IO>> for Box<dyn AsyncReadWrite>
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn from(stream: ServerStream<IO>) -> Self {
		match stream {
			ServerStream::Raw(stream) => stream,
			ServerStream::Tls(stream) => stream,
		}
	}
}

// -------------------------------------------
//                Outbound
// -------------------------------------------

/// Settings for websocket connection.
pub struct Outbound {
	headers: http::HeaderMap<http::HeaderValue>,
	path: String,
	host: Option<DomainName>,
	tls: Option<tls::Outbound>,
}

impl Outbound {
	#[inline]
	pub async fn connect(
		&self,
		addr: &SocksAddr,
		context: &dyn ProxyContext,
	) -> io::Result<Box<dyn AsyncReadWrite>> {
		self.connect_stream(context.dial_tcp(addr).await?, addr)
			.await
			.map(Into::into)
	}

	pub async fn connect_stream<IO>(
		&self,
		stream: IO,
		addr: &SocksAddr,
	) -> io::Result<ClientStream<IO>>
	where
		IO: 'static + AsyncRead + AsyncWrite + Unpin,
	{
		debug!("Initiating Websocket transport request to '{}'.", addr);
		if let Some(tls) = &self.tls {
			let stream = tls.connect_stream(stream, addr).await?;
			Ok(ClientStream::Tls(Box::new(
				self.connect_ws_only(stream, addr).await?,
			)))
		} else {
			Ok(ClientStream::Raw(Box::new(
				self.connect_ws_only(stream, addr).await?,
			)))
		}
	}

	pub async fn connect_ws_only<IO>(
		&self,
		stream: IO,
		addr: &SocksAddr,
	) -> io::Result<PlainStream<IO>>
	where
		IO: 'static + AsyncRead + AsyncWrite + Unpin,
	{
		let request = {
			let url = self.make_url(addr)?;
			// Make request for websocket connection
			let mut req = http::Request::builder();
			// Make headers
			for (key, value) in &self.headers {
				req = req.header(key, value);
			}
			// Finish
			req.uri(url).body(()).map_err(|e| {
				io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("failed to make HTTP request ({})", e),
				)
			})?
		};
		trace!("Websocket request: {:?}", request);
		let stream = websocket::connect_stream(stream, request).await?;
		Ok(stream)
	}

	fn make_url(&self, addr: &SocksAddr) -> io::Result<Uri> {
		let scheme = if self.tls.is_some() { "wss" } else { "ws" };
		let host = if let Some(host) = &self.host {
			SocksAddr::new(host.clone().into(), addr.port).to_string()
		} else {
			addr.to_string()
		};
		Uri::builder()
			.scheme(scheme)
			.authority(host.as_str())
			.path_and_query(&self.path)
			.build()
			.map_err(|e| {
				io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("failed to make URL ({})", e),
				)
			})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct OutboundBuilder {
	/// HTTP headers.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub headers: HashMap<String, String>,
	/// HTTP path for the websocket.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub path: String,
	/// Host for HTTP request.
	/// The value in `addr` field will be used if empty.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub host: String,
	/// TLS settings.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tls: Option<tls::OutboundBuilder>,
}

impl OutboundBuilder {
	/// Create a [`Outbound`].
	///
	/// # Errors
	///
	/// Returns [`BuildError::PathNotStartsWithSlash`] if `self.path` is not empty
	/// and not starting with '/'.
	///
	/// Returns [`BuildError::Tls`] if there are any errors in TLS configuration.
	pub fn build(self) -> Result<Outbound, BuildError> {
		let tls = self.tls.map(tls::OutboundBuilder::build).transpose()?;
		let headers = {
			let mut headers = http::HeaderMap::new();
			for (key, value) in self.headers {
				let key = http::header::HeaderName::from_str(&key)
					.map_err(|e| BuildError::InvalidHeaderName(key, e))?;
				let value = http::header::HeaderValue::from_str(&value)
					.map_err(|e| BuildError::InvalidHeaderValue(value, e))?;
				headers.append(key, value);
			}
			headers
		};
		let host = if self.host.is_empty() {
			None
		} else {
			Some(DomainName::from_str(&self.host).map_err(BuildError::InvalidHost)?)
		};
		Ok(Outbound {
			headers,
			path: self.path,
			host,
			tls,
		})
	}
}

impl DisplayInfo for OutboundBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.tls.is_none() {
			f.write_str("ws-out")
		} else {
			f.write_str("wss-out")
		}
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.tls.is_none() {
			f.write_str("ws-out")
		} else {
			f.write_str("wss-out")
		}?;
		let mut content = String::new();
		if !self.host.is_empty() {
			content.push('(');
			write!(&mut content, "host:'{}'", &self.host)?;
		}
		if !self.path.is_empty() {
			content.push(if content.is_empty() { '(' } else { ',' });
			write!(&mut content, "path:'{}'", &self.path)?;
		}
		if !content.is_empty() {
			write!(f, "{content})")?;
		}
		Ok(())
	}
}

// -------------------------------------------
//                Inbound
// -------------------------------------------

/// Settings for websocket connection.
pub struct Inbound {
	headers: HashMap<String, String>,
	path: String,
	tls: Option<tls::Inbound>,
}

impl Inbound {
	pub async fn accept<IO>(&self, stream: IO) -> io::Result<ServerStream<IO>>
	where
		IO: AsyncRead + AsyncWrite + Unpin,
	{
		if let Some(tls) = &self.tls {
			let stream = tls.accept(stream).await?;
			Ok(ServerStream::Tls(Box::new(
				websocket::accept(stream, &self.headers, &self.path).await?,
			)))
		} else {
			Ok(ServerStream::Raw(Box::new(
				websocket::accept(stream, &self.headers, &self.path).await?,
			)))
		}
	}
}

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug, Clone)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct InboundBuilder {
	/// HTTP headers.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub headers: HashMap<String, String>,
	/// HTTP path for the websocket. If set, it must starts with '/'.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub path: String,
	/// TLS settings.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tls: Option<tls::InboundBuilder>,
}

impl InboundBuilder {
	/// Create a [`Inbound`].
	///
	/// # Errors
	///
	/// Returns [`BuildError::PathNotStartsWithSlash`] if `self.path` is not empty
	/// and not starting with '/'.
	///
	/// Returns [`BuildError::Tls`] if there are any errors in TLS configuration `self.tls`.
	pub fn build(self) -> Result<Inbound, BuildError> {
		if is_path_invalid(&self.path) {
			return Err(BuildError::PathNotStartsWithSlash(self.path));
		}
		let tls = self.tls.map(tls::InboundBuilder::build).transpose()?;
		Ok(Inbound {
			headers: self.headers,
			path: self.path,
			tls,
		})
	}
}

impl DisplayInfo for InboundBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.tls.is_none() {
			f.write_str("ws-in")
		} else {
			f.write_str("wss-in")
		}
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.tls.is_none() {
			f.write_str("ws-in")
		} else {
			f.write_str("wss-in")
		}?;
		if !self.path.is_empty() {
			write!(f, "(path:'{}')", self.path)?;
		}
		Ok(())
	}
}

fn is_path_invalid(path: &str) -> bool {
	!path.is_empty() && !path.starts_with('/')
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_outbound_display_info() {
		let mut s = OutboundBuilder {
			headers: HashMap::new(),
			path: String::new(),
			host: String::new(),
			tls: None,
		};
		assert_eq!(s.brief().to_string(), "ws-out");
		assert_eq!(s.detail().to_string(), "ws-out");
		s.tls = Some(Default::default());
		assert_eq!(s.brief().to_string(), "wss-out");
		assert_eq!(s.detail().to_string(), "wss-out");
		s.path = "some_path".into();
		assert_eq!(s.brief().to_string(), "wss-out");
		assert_eq!(s.detail().to_string(), "wss-out(path:'some_path')");
		s.path = String::new();
		s.host = "localhost".into();
		assert_eq!(s.brief().to_string(), "wss-out");
		assert_eq!(s.detail().to_string(), "wss-out(host:'localhost')");
		s.path = "some_path".into();
		s.host = "localhost".into();
		assert_eq!(s.brief().to_string(), "wss-out");
		assert_eq!(
			s.detail().to_string(),
			"wss-out(host:'localhost',path:'some_path')"
		);
	}

	#[test]
	fn test_inbound_display_info() {
		let mut s = InboundBuilder {
			headers: HashMap::new(),
			path: String::new(),
			tls: None,
		};
		assert_eq!(s.brief().to_string(), "ws-in");
		assert_eq!(s.detail().to_string(), "ws-in");
		s.tls = Some(super::tls::InboundBuilder {
			alpns: Default::default(),
			cert_file: String::new().into(),
			key_file: String::new().into(),
		});
		assert_eq!(s.brief().to_string(), "wss-in");
		assert_eq!(s.detail().to_string(), "wss-in");
		s.path = "some_path".into();
		assert_eq!(s.brief().to_string(), "wss-in");
		assert_eq!(s.detail().to_string(), "wss-in(path:'some_path')");
	}
}
