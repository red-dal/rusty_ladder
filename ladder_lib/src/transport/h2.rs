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
	protocol::{AsyncReadWrite, CompositeBytesStream, ProxyContext},
};
use bytes::{Buf, Bytes};
use futures::{ready, Future};
use h2::{client, server, RecvStream, SendStream};
use http::{Request, Response, Uri};
use std::{
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
	#[error("non-empty path '{0}' does not start with '/'")]
	PathNotStartsWithSlash(String),
	#[error("tls ({0})")]
	Tls(#[from] crate::utils::tls::ConfigError),
}

pub struct Outbound {
	path: String,
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

		let uri = {
			let scheme = if self.tls.is_some() { "https" } else { "http" };
			let uri = format!("{}://www.example.com{}", scheme, self.path);
			uri.parse::<Uri>().map_err(|err| {
				io::Error::new(
					io::ErrorKind::Other,
					format!("Incorrect URI '{}' ({})", uri, err),
				)
			})?
		};

		let request = Request::put(uri)
			.version(http::Version::HTTP_2)
			.body(())
			.unwrap();

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

#[derive(Clone, Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct OutboundBuilder {
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
		let path = check_path(self.path)?;
		let tls = self.tls.map(tls::OutboundBuilder::build).transpose()?;
		Ok(Outbound { path, tls })
	}
}

pub struct Inbound {
	path: String,
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

		let required_path = if self.path.is_empty() {
			"/"
		} else {
			&self.path
		};

		trace!("HTTP2 request: {:?}", request);

		if request.uri().path() != required_path {
			// send response
			let response = Response::builder()
				.status(http::StatusCode::NOT_FOUND)
				.body(())
				.unwrap();

			if let Err(err) = send_response.send_response(response, true) {
				error!("Error when sending h2 response {}", err);
			};

			let msg = format!(
				"invalid h2 path '{}', '{}' required",
				request.uri().path(),
				required_path
			);
			return Err(io::Error::new(io::ErrorKind::Other, msg));
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
}

#[derive(Debug, Clone)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct InboundBuilder {
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
		let path = check_path(self.path)?;
		let tls = self.tls.map(tls::InboundBuilder::build).transpose()?;
		Ok(Inbound { path, tls })
	}
}

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
fn check_path(path: String) -> Result<String, BuildError> {
	if !path.is_empty() && !path.starts_with('/') {
		Err(BuildError::PathNotStartsWithSlash(path))
	} else {
		Ok(path)
	}
}
