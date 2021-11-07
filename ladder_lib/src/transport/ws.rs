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

use super::{http_utils, tls};
use crate::{
	prelude::*,
	protocol::BytesStream,
	utils::websocket::{self, Stream as WsStream},
};
use std::{collections::HashMap, io};

pub type PlainStream<IO> = WsStream<IO>;
pub type SecureClientStream<IO> = WsStream<tls::ClientStream<IO>>;
pub type SecureServerStream<IO> = WsStream<tls::ServerStream<IO>>;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
	#[error("tls ({0})")]
	Tls(#[from] crate::utils::tls::ConfigError),
	#[error("non-empty path '{0}' does not start with '/'")]
	PathNotStartsWithSlash(String),
}

// Use box because SecureClientStream is too big
pub enum ClientStream<IO: AsyncRead + AsyncWrite + Unpin> {
	Raw(Box<PlainStream<IO>>),
	Tls(Box<SecureClientStream<IO>>),
}

impl<IO> From<ClientStream<IO>> for BytesStream
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn from(s: ClientStream<IO>) -> Self {
		match s {
			ClientStream::Raw(stream) => {
				let (r, w) = tokio::io::split(stream);
				BytesStream::new(Box::new(r), Box::new(w))
			}
			ClientStream::Tls(stream) => {
				let (r, w) = tokio::io::split(stream);
				BytesStream::new(Box::new(r), Box::new(w))
			}
		}
	}
}

pub enum ServerStream<IO: AsyncRead + AsyncWrite + Unpin> {
	Raw(Box<PlainStream<IO>>),
	Tls(Box<SecureServerStream<IO>>),
}

impl<IO> From<ServerStream<IO>> for BytesStream
where
	IO: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
	fn from(s: ServerStream<IO>) -> Self {
		match s {
			ServerStream::Raw(stream) => {
				let (r, w) = tokio::io::split(*stream);
				BytesStream::new(Box::new(r), Box::new(w))
			}
			ServerStream::Tls(stream) => {
				let (r, w) = tokio::io::split(*stream);
				BytesStream::new(Box::new(r), Box::new(w))
			}
		}
	}
}

/// Settings for websocket connection.
pub struct Outbound {
	headers: HashMap<String, String>,
	path: String,
	host: String,
	tls: Option<tls::Outbound>,
}

impl Outbound {
	pub async fn connect<IO>(&self, stream: IO, addr: &SocksAddr) -> io::Result<ClientStream<IO>>
	where
		IO: 'static + AsyncRead + AsyncWrite + Unpin,
	{
		debug!("Initiating Websocket transport request to '{}'.", addr);
		if let Some(tls) = &self.tls {
			let stream = tls.connect(stream, addr).await?;
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
		// make request object
		let uri = {
			let domain = if self.host.is_empty() {
				addr.to_string().into()
			} else {
				Cow::Borrowed(self.host.as_str())
			};
			http_utils::make_ws_uri(self.tls.is_some(), &domain, &self.path)
				.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
		};
		trace!("Websocket URI: {}", uri);
		let mut request = http::Request::builder().uri(uri);
		// fill request headers
		for (key, value) in &self.headers {
			request = request.header(key, value);
		}

		let request = request.body(()).expect("cannot construct HTTP request");
		trace!("Websocket request: {:?}", request);

		let stream = websocket::connect_stream(stream, request).await?;
		Ok(stream)
	}
}

#[derive(Clone, Debug)]
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
		Ok(Outbound {
			headers: self.headers,
			path: self.path,
			host: self.host,
			tls,
		})
	}
}

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

fn is_path_invalid(path: &str) -> bool {
	!path.is_empty() && !path.starts_with('/')
}
