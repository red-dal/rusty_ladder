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

use super::tls;
use crate::{
	prelude::*,
	protocol::{socks_addr::DomainName, AsyncReadWrite, CompositeBytesStream, ProxyContext},
};
use bytes::{Buf, Bytes};
use futures::{ready, Future};
use h2::{client, server, RecvStream, SendStream};
use http::{Request, Response, Uri};
use std::{
	collections::HashSet,
	io,
	pin::Pin,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CLOSED: bool = true;
const NOT_CLOSED: bool = !CLOSED;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
	#[error("domain '{0}' is invalid ({1})")]
	InvalidHost(String, BoxStdErr),
	#[error("non-empty path '{0}' does not start with '/'")]
	PathNotStartsWithSlash(String),
	#[error("tls ({0})")]
	Tls(#[from] crate::utils::tls::ConfigError),
}

// -------------------------------------------------------------
//                          Outbound
// -------------------------------------------------------------

pub struct Outbound {
	req_url: Uri,
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

	#[inline]
	pub async fn connect_stream<RW>(
		&self,
		stream: RW,
		addr: &SocksAddr,
	) -> io::Result<Box<dyn AsyncReadWrite>>
	where
		RW: 'static + AsyncRead + AsyncWrite + Send + Unpin,
	{
		info!("Establishing H2 connection to '{}'", addr);
		let (r, w) = if let Some(tls) = &self.tls {
			let stream = tls.connect_stream(stream, addr).await?;
			self.priv_connect(stream, addr).await?
		} else {
			self.priv_connect(stream, addr).await?
		};

		Ok(Box::new(CompositeBytesStream { r, w }))
	}

	async fn priv_connect<RW>(
		&self,
		stream: RW,
		_addr: &SocksAddr,
	) -> io::Result<(ReadHalf, WriteHalf)>
	where
		RW: 'static + AsyncRead + AsyncWrite + Send + Unpin,
	{
		let (send_request, conn) = client::handshake(stream).await.map_err(h2_to_io_err)?;
		let is_closed = Arc::new(AtomicBool::new(NOT_CLOSED));
		tokio::spawn(async move {
			if let Err(err) = conn.await {
				error!("H2 connection error: {}", err);
			};
		});
		let mut send_request = send_request.ready().await.map_err(h2_to_io_err)?;

		let request = Request::put(self.req_url.clone())
			.version(http::Version::HTTP_2)
			.body(())
			.expect("Building HTTP request should not failed");

		trace!("HTTP2 request: {:?}", request);

		let (response_fut, send_stream) = send_request
			.send_request(request, false)
			.map_err(h2_to_io_err)?;

		let response = response_fut.await.map_err(h2_to_io_err)?;
		if response.status() != 200 {
			return Err(io::Error::new(
				io::ErrorKind::Other,
				format!("HTTP response status code {}", response.status()),
			));
		}

		let recv_stream = response.into_body();

		let read_half = ReadHalf::new(recv_stream);
		let write_half = WriteHalf {
			inner: send_stream,
			is_closed,
		};

		Ok((read_half, write_half))
	}
}

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct OutboundBuilder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub host: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub path: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tls: Option<tls::OutboundBuilder>,
}

impl OutboundBuilder {
	/// Create an h2 [`Outbound`].
	///
	/// # Errors
	///
	/// Returns [`BuildError::PathNotStartsWithSlash`] if `self.path` is not empty
	/// and not starting with '/'.
	///
	/// Returns [`BuildError::Tls`] if there are any errors in TLS configuration.
	pub fn build(self) -> Result<Outbound, BuildError> {
		let tls = self.tls.map(tls::OutboundBuilder::build).transpose()?;
		let req_url = make_request_url(&self.path, &self.host, tls.is_some())?;
		Ok(Outbound { req_url, tls })
	}
}

const DEFAULT_HOST: &str = "www.example.com";

fn make_request_url(path: &str, host: &str, use_tls: bool) -> Result<Uri, BuildError> {
	const HTTPS: &str = "https";
	const HTTP: &str = "http";

	let host = if host.is_empty() { DEFAULT_HOST } else { host };
	let scheme = if use_tls { HTTPS } else { HTTP };
	Uri::builder()
		.scheme(scheme)
		.authority(host)
		.path_and_query(path)
		.build()
		.map_err(|e| BuildError::InvalidHost(host.into(), e.into()))
}

#[cfg(test)]
mod outbound_tests {
	use super::*;

	#[test]
	fn test_make_request_url() {
		fn check(expected: &str, host: &str, path: &str, use_tls: bool) {
			let expected = Uri::from_str(expected).unwrap();
			let output = make_request_url(path, host, use_tls).unwrap();
			assert_eq!(expected, output);
		}

		check("http://www.example.com", "", "/", false);
		check("https://www.example.com", "", "/", true);

		check("http://www.example.com/testpath", "", "/testpath", false);
		check("https://www.example.com/testpath", "", "/testpath", true);

		check("http://aaa.bbb", "aaa.bbb", "/", false);
		check("http://aaa.bbb/testpath", "aaa.bbb", "/testpath", false);

		check("http://aaa.bbb", "aaa.bbb", "", false);
		check("http://aaa.bbb/testpath", "aaa.bbb", "/testpath", false);
	}
}

// -------------------------------------------------------------
//                          Inbound
// -------------------------------------------------------------
pub struct Inbound {
	allowed_hosts: HashSet<DomainName>,
	allowed_path: String,
	tls: Option<tls::Inbound>,
}

impl Inbound {
	#[inline]
	pub async fn accept<RW>(&self, stream: RW) -> io::Result<Box<dyn AsyncReadWrite>>
	where
		RW: 'static + AsyncRead + AsyncWrite + Unpin + Send,
	{
		if let Some(tls) = &self.tls {
			self.priv_accept(tls.accept(stream).await?).await
		} else {
			self.priv_accept(stream).await
		}
	}

	async fn priv_accept<RW>(&self, stream: RW) -> io::Result<Box<dyn AsyncReadWrite>>
	where
		RW: 'static + AsyncRead + AsyncWrite + Unpin + Send,
	{
		let mut conn = h2::server::handshake(stream).await.map_err(h2_to_io_err)?;

		let (request, mut send_response) = if let Some(r) = conn.accept().await {
			r.map_err(h2_to_io_err)?
		} else {
			conn.graceful_shutdown();
			if let Err(err) = CloseServerFuture::new(conn).await {
				return Err(io::Error::new(
					io::ErrorKind::Other,
					format!("cannot close H2 connection ({})", err),
				));
			}
			return Err(io::Error::new(
				io::ErrorKind::Other,
				"no request from H2 client",
			));
		};

		let is_closed = Arc::new(AtomicBool::new(NOT_CLOSED));
		{
			let is_closed = is_closed.clone();
			tokio::spawn(async move {
				if let Err(err) = CloseServerFuture::new_with_switch(conn, is_closed).await {
					if let Some(err) = err.get_io() {
						if err.kind() == io::ErrorKind::NotConnected {
							// Ignore error if connection is already closed
							debug!("H2 connection already closed ({})", err);
							return;
						}
					}
					error!("Error when closing H2 connection ({})", err);
				};
			});
		}
		if let Err(e) = self.check_request(&request) {
			// Send response to client first
			let response = Response::builder()
				.status(http::StatusCode::NOT_FOUND)
				.body(())
				.unwrap();
			if let Err(err) = send_response.send_response(response, true) {
				error!("Error when sending h2 response {}", err);
			};
			return Err(e);
		}

		trace!("Sending response");

		let send_stream = {
			let response = Response::builder()
				.status(http::StatusCode::OK)
				.body(())
				.unwrap();
			send_response
				.send_response(response, false)
				.map_err(h2_to_io_err)?
		};

		let recv_stream = request.into_body();

		trace!("Returning stream");

		let r = ReadHalf::new(recv_stream);
		let w = WriteHalf {
			inner: send_stream,
			is_closed,
		};

		Ok(Box::new(CompositeBytesStream { r, w }))
	}

	fn check_request<B: std::fmt::Debug>(&self, req: &http::Request<B>) -> io::Result<()> {
		debug_assert!(!self.allowed_hosts.is_empty());
		// Verifying client
		trace!("Verifying client's request: {:?}", req);
		// Check if URL path match self.allowed_path
		let allowed_path = if self.allowed_path.is_empty() {
			"/"
		} else {
			&self.allowed_path
		};
		if req.uri().path() != allowed_path {
			// send response
			let msg = format!("invalid path '{}'", req.uri().path());
			return Err(io::Error::new(io::ErrorKind::Other, msg));
		}
		// Check if URL host is in self.allowed_hosts
		let url_host = req.uri().host().ok_or_else(|| {
			io::Error::new(io::ErrorKind::InvalidData, "HTTP request URL missing host")
		})?;
		if !self.allowed_hosts.contains(url_host) {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("invalid host '{}'", url_host),
			));
		}
		Ok(())
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
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub hosts: Vec<String>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub path: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub tls: Option<tls::InboundBuilder>,
}

impl InboundBuilder {
	/// Create an h2 [`Inbound`].
	///
	/// # Errors
	///
	/// Returns [`BuildError::PathNotStartsWithSlash`] if `self.path` is not empty
	/// and not starting with '/'.
	///
	/// Returns [`BuildError::Tls`] if there are any errors in TLS configuration.
	pub fn build(self) -> Result<Inbound, BuildError> {
		let default_hosts = [String::from(DEFAULT_HOST)];
		let path = check_path(&self.path)?;
		let tls = self.tls.map(tls::InboundBuilder::build).transpose()?;
		let hosts = {
			// Use a default host if self.hosts is empty
			let old_hosts = if self.hosts.is_empty() {
				default_hosts.as_slice()
			} else {
				self.hosts.as_slice()
			};
			// Fill hosts
			let mut hosts = HashSet::with_capacity(old_hosts.len());
			for host in old_hosts {
				hosts.insert(
					DomainName::from_str(&host)
						.map_err(|e| BuildError::InvalidHost(host.clone(), e.into()))?,
				);
			}
			hosts
		};
		Ok(Inbound {
			allowed_hosts: hosts,
			allowed_path: path.into(),
			tls,
		})
	}
}

#[cfg(test)]
mod inbound_tests {
	use super::*;

	#[test]
	fn test_inbound_check_request() {
		fn check(
			allowed_hosts: &[&str],
			allowed_path: &str,
			host: &str,
			path: &str,
		) -> io::Result<()> {
			Inbound {
				allowed_hosts: allowed_hosts
					.iter()
					.map(|h| DomainName::from_str(h).unwrap())
					.collect(),
				allowed_path: allowed_path.into(),
				tls: None,
			}
			.check_request(
				&http::Request::builder()
					.uri(
						http::Uri::builder()
							.scheme("http")
							.authority(host)
							.path_and_query(path)
							.build()
							.unwrap(),
					)
					.body(())
					.unwrap(),
			)
		}
		check(&["a.b", "c.d"], "", "a.b", "").unwrap();
		check(&["a.b", "c.d"], "/examplepath", "a.b", "/examplepath").unwrap();
		// Wrong host
		check(&["a.b", "c.d"], "", "wrong.host", "").unwrap_err();
		check(
			&["a.b", "c.d"],
			"/examplepath",
			"wrong.host",
			"/examplepath",
		)
		.unwrap_err();
		// Wrong path
		check(&["a.b", "c.d"], "", "a.b", "/wrongpath").unwrap_err();
		check(&["a.b", "c.d"], "/examplepath", "a.b", "").unwrap_err();
		// Wrong host and path
		check(&["a.b", "c.d"], "", "wrong.host", "/wrongpath").unwrap_err();
	}
}

// -------------------------------------------------------------
//                               IO
// -------------------------------------------------------------

pub enum ReadState {
	Reading,
	Buffering { data: Bytes },
}

pub struct ReadHalf {
	inner: RecvStream,
	state: ReadState,
}

impl ReadHalf {
	pub fn new(inner: RecvStream) -> Self {
		Self {
			inner,
			state: ReadState::Reading,
		}
	}
}

impl AsyncRead for ReadHalf {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let me = self.get_mut();

		match &mut me.state {
			ReadState::Reading => {
				// try to read data
				if let Some(res) = ready!(me.inner.poll_data(cx)) {
					// not eof
					let mut data = res.map_err(h2_to_io_err)?;
					trace!("H2 data len: {}, buf len: {}", data.len(), buf.remaining());
					if data.len() <= buf.remaining() {
						// data can fit in buf
						// no need for buffering
						buf.put_slice(&data);
						Ok(()).into()
					} else {
						// data needs to buffer
						let len = buf.remaining();

						let buffered_data = data.split_off(len);

						buf.put_slice(&data);
						// change state
						trace!(
							"Entering buffered state, data remaining len: {}",
							buffered_data.len()
						);
						me.state = ReadState::Buffering {
							data: buffered_data,
						};
						Ok(()).into()
					}
				} else {
					// eof
					Ok(()).into()
				}
			}
			ReadState::Buffering { data } => {
				trace!("Current HTTP2 buffered data len: {} bytes", data.len());
				if data.len() <= buf.remaining() {
					buf.put_slice(data);
					me.state = ReadState::Reading;
				} else {
					let len = std::cmp::min(data.remaining(), buf.remaining());
					buf.put_slice(&data[..len]);
					data.advance(len);
				}
				Ok(()).into()
			}
		}
	}
}

pub struct WriteHalf {
	inner: SendStream<Bytes>,
	is_closed: Arc<AtomicBool>,
}

impl AsyncWrite for WriteHalf {
	fn poll_write(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<Result<usize, io::Error>> {
		self.get_mut()
			.inner
			.send_data(Bytes::copy_from_slice(buf), false)
			.map_err(h2_to_io_err)?;

		Ok(buf.len()).into()
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		Ok(()).into()
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		self.is_closed.store(CLOSED, Ordering::Relaxed);
		self.get_mut()
			.inner
			.send_data(Bytes::new(), true)
			.map_err(h2_to_io_err)?;
		Ok(()).into()
	}
}

fn h2_to_io_err(err: h2::Error) -> io::Error {
	if err.is_io() {
		err.into_io().unwrap()
	} else {
		std::io::Error::new(io::ErrorKind::Other, err)
	}
}

struct CloseServerFuture<RW, B>
where
	RW: AsyncRead + AsyncWrite + Unpin,
	B: 'static + Buf,
{
	conn: server::Connection<RW, B>,
	is_closed: Option<Arc<AtomicBool>>,
}

impl<RW, B> CloseServerFuture<RW, B>
where
	RW: AsyncRead + AsyncWrite + Unpin,
	B: 'static + Buf,
{
	fn new(conn: server::Connection<RW, B>) -> Self {
		Self {
			conn,
			is_closed: None,
		}
	}

	fn new_with_switch(conn: server::Connection<RW, B>, switch: Arc<AtomicBool>) -> Self {
		Self {
			conn,
			is_closed: Some(switch),
		}
	}
}

impl<RW, B> Future for CloseServerFuture<RW, B>
where
	RW: AsyncRead + AsyncWrite + Unpin,
	B: 'static + Buf,
{
	type Output = Result<(), h2::Error>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let me = self.get_mut();
		if let Some(is_closed) = &me.is_closed {
			if is_closed.load(Ordering::Relaxed) == CLOSED {
				me.conn.graceful_shutdown();
				me.is_closed = None;
			}
		}
		me.conn.poll_closed(cx)
	}
}

#[inline]
fn check_path(path: &str) -> Result<&str, BuildError> {
	if path.is_empty() {
		return Ok("/");
	}
	if !path.starts_with('/') {
		return Err(BuildError::PathNotStartsWithSlash(path.into()));
	}
	Ok(path)
}
