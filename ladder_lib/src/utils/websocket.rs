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

use crate::{prelude::*, protocol::BytesStream};
use async_tungstenite::{
	tokio::{accept_hdr_async, client_async, TokioAdapter},
	tungstenite::{
		error::Error as WsError,
		handshake::server::{Callback, ErrorResponse, Request, Response},
	},
	WebSocketStream,
};
use bytes::Bytes;
use futures::{ready, FutureExt, Sink as ItemSink, Stream as ItemStream};
use log::debug;
use std::{
	collections::HashMap,
	io,
	pin::Pin,
	task::{Context, Poll},
};
use tokio::io::ReadBuf;

pub use async_tungstenite::tungstenite::protocol::Message;

pub type MessageStream<IO> = WebSocketStream<TokioAdapter<IO>>;
pub type Stream<IO> = StreamWrapper<MessageStream<IO>>;

pub async fn connect_message_stream<IO>(
	stream: IO,
	request: Request,
) -> io::Result<MessageStream<IO>>
where
	IO: 'static + AsyncRead + AsyncWrite + Unpin,
{
	debug!(
		"Establishing Websocket connection with request: {:?}",
		request
	);
	// connect
	let (stream, response) = match client_async(request, stream).await {
		Ok(res) => res,
		Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err)),
	};
	if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
		let msg = format!(
			"Incorrect HTTP response status code during websocket connection: {}",
			response.status()
		);
		return Err(io::Error::new(io::ErrorKind::Other, msg));
	}
	debug!("Websocket connection established");
	Ok(stream)
}

pub async fn connect_stream<IO>(stream: IO, request: Request) -> io::Result<Stream<IO>>
where
	IO: 'static + AsyncRead + AsyncWrite + Unpin,
{
	connect_message_stream(stream, request)
		.map(|res| res.map(StreamWrapper::new))
		.await
}

pub async fn accept<'a, IO>(
	stream: IO,
	headers: &'a HashMap<String, String>,
	path: &'a str,
) -> io::Result<Stream<IO>>
where
	IO: AsyncRead + AsyncWrite + Unpin,
{
	accept_message_stream(stream, headers, path)
		.map(|res| res.map(StreamWrapper::new))
		.await
}

pub async fn accept_message_stream<'a, IO>(
	stream: IO,
	headers: &'a HashMap<String, String>,
	path: &'a str,
) -> io::Result<MessageStream<IO>>
where
	IO: AsyncRead + AsyncWrite + Unpin,
{
	if !path.is_empty() && !path.starts_with('/') {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"Websocket path should starts with '/'",
		));
	}
	accept_hdr_async(stream, CheckHeaderAndPath::new(headers, path))
		.await
		.map_err(|e| match e {
			WsError::Io(e) => e,
			_ => io::Error::new(io::ErrorKind::Other, e),
		})
}

struct CheckHeaderAndPath<'a> {
	headers: &'a HashMap<String, String>,
	path: &'a str,
}

impl<'a> CheckHeaderAndPath<'a> {
	pub fn new(headers: &'a HashMap<String, String>, path: &'a str) -> Self {
		Self { headers, path }
	}
}

impl<'a> Callback for CheckHeaderAndPath<'a> {
	fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
		if !self.path.is_empty() && request.uri().path() != self.path {
			debug!(
				"Websocket request path mismatch, '{}' expected, '{}' received.",
				self.path,
				request.uri().path(),
			);
			return Err(new_404_response(None));
		}

		for (key, value) in self.headers {
			if let Some(req_value) = request.headers().get(key.as_str()) {
				if req_value != value.as_str() {
					debug!(
						"Websocket request header value for key '{}' is incorrect, '{}' expected.",
						key,
						value.as_str(),
					);
					return Err(new_404_response(None));
				}
			} else {
				debug!("Websocket request missing header key '{}'", key);
				return Err(new_404_response(None));
			}
		}

		Ok(response)
	}
}

fn new_404_response<B>(body: B) -> http::Response<B> {
	let builder = http::response::Builder::new().status(404);
	builder
		.body(body)
		.expect("Unable to construct HTTP response.")
}

#[derive(Debug)]
enum ReadingState {
	Reading,
	Buffering(PollBuffer<Vec<u8>>),
}

#[derive(Debug)]
pub struct StreamWrapper<S>
where
	S: ItemStream<Item = Result<Message, WsError>> + ItemSink<Message, Error = WsError> + Unpin,
{
	inner: S,
	state: ReadingState,
}

impl<S> StreamWrapper<S>
where
	S: ItemStream<Item = Result<Message, WsError>> + ItemSink<Message, Error = WsError> + Unpin,
{
	fn new(inner: S) -> Self {
		Self {
			inner,
			state: ReadingState::Reading,
		}
	}
}

impl<S> AsyncRead for StreamWrapper<S>
where
	S: ItemStream<Item = Result<Message, WsError>> + ItemSink<Message, Error = WsError> + Unpin,
{
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		dst: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let me = self.get_mut();
		loop {
			match &mut me.state {
				ReadingState::Reading => {
					let res: Option<Result<Message, WsError>> =
						ready!(Pin::new(&mut me.inner).poll_next(cx));
					if let Some(res) = res {
						match res.map_err(to_io_err)? {
							Message::Binary(buf) => {
								me.state = ReadingState::Buffering(PollBuffer::new(buf));
							}
							Message::Text(buf) => {
								let buf: Bytes = buf.into();
								me.state = ReadingState::Buffering(PollBuffer::new(buf.to_vec()));
							}
							Message::Close(_) => {
								return Ok(()).into();
							}
							_ => {
								return Err(io::Error::new(
									io::ErrorKind::Other,
									"unsupported websocket message type",
								))
								.into();
							}
						}
					} else {
						// EOF reached.
						return Ok(()).into();
					}
				}
				ReadingState::Buffering(buf) => {
					let is_empty = buf.copy_to(dst);
					if is_empty {
						me.state = ReadingState::Reading;
					}
					return Ok(()).into();
				}
			}
		}
	}
}

impl<S> AsyncWrite for StreamWrapper<S>
where
	S: ItemStream<Item = Result<Message, WsError>> + ItemSink<Message, Error = WsError> + Unpin,
{
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<Result<usize, io::Error>> {
		let me = self.get_mut();
		if let Err(err) = ready!(Pin::new(&mut me.inner).poll_ready(cx)) {
			return Err(to_io_err(err)).into();
		};
		if let Err(err) = Pin::new(&mut me.inner).start_send(Message::Binary(buf.to_vec())) {
			return Err(to_io_err(err)).into();
		};
		Ok(buf.len()).into()
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let me = self.get_mut();
		if let Err(err) = ready!(Pin::new(&mut me.inner).poll_flush(cx)) {
			return Err(to_io_err(err)).into();
		};
		Ok(()).into()
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		let me = self.get_mut();
		if let Err(err) = ready!(Pin::new(&mut me.inner).poll_close(cx)) {
			return Err(to_io_err(err)).into();
		};
		Ok(()).into()
	}
}

#[inline]
fn to_io_err(err: WsError) -> io::Error {
	if let WsError::Io(err) = err {
		return err;
	}
	io::Error::new(io::ErrorKind::Other, err)
}

impl<S> From<StreamWrapper<S>> for BytesStream
where
	S: 'static
		+ ItemStream<Item = Result<Message, WsError>>
		+ ItemSink<Message, Error = WsError>
		+ Send
		+ Sync
		+ Unpin,
{
	fn from(stream: StreamWrapper<S>) -> Self {
		let (rh, wh) = tokio::io::split(stream);
		BytesStream::new(Box::new(rh), Box::new(wh))
	}
}

#[derive(Debug)]
pub struct PollBuffer<T: AsRef<[u8]>> {
	pub inner: T,
	pub pos: usize,
}

impl<T: AsRef<[u8]>> PollBuffer<T> {
	pub fn new(inner: T) -> Self {
		Self { inner, pos: 0 }
	}

	#[inline]
	pub fn remaining(&self) -> usize {
		self.inner.as_ref().len() - self.pos
	}

	/// Returns `true` if `self.pos` has reached the end.
	pub fn copy_to(&mut self, dst: &mut ReadBuf<'_>) -> bool {
		let mut is_empty = false;

		let copy_len = std::cmp::min(self.remaining(), dst.remaining());
		let next_pos = self.pos + copy_len;
		dst.put_slice(&self.inner.as_ref()[self.pos..next_pos]);

		self.pos = next_pos;
		if self.pos == self.inner.as_ref().len() {
			is_empty = true;
		}

		is_empty
	}
}

#[cfg(test)]
mod tests {
	use tokio::io::ReadBuf;

	use super::PollBuffer;

	#[test]
	fn test_poll_buffer() {
		let mut poll_buf = PollBuffer::new(vec![3_u8; 256]);
		for (n, i) in poll_buf.inner.iter_mut().enumerate() {
			*i = n as u8;
		}
		{
			assert_eq!(poll_buf.pos, 0);

			let mut buf = vec![0_u8; 100];
			let mut read_buf = ReadBuf::new(&mut buf);
			let is_empty = poll_buf.copy_to(&mut read_buf);

			assert!(!is_empty);
			assert_eq!(read_buf.remaining(), 0);
			assert_eq!(poll_buf.pos, 100);
			assert_eq!(
				read_buf.filled(),
				&poll_buf.inner[poll_buf.pos - read_buf.filled().len()..poll_buf.pos]
			);
		}
		{
			assert_eq!(poll_buf.pos, 100);

			let mut buf = vec![0_u8; 100];
			let mut read_buf = ReadBuf::new(&mut buf);
			let is_empty = poll_buf.copy_to(&mut read_buf);

			assert!(!is_empty);
			assert_eq!(read_buf.remaining(), 0);
			assert_eq!(poll_buf.pos, 200);
			assert_eq!(
				read_buf.filled(),
				&poll_buf.inner[poll_buf.pos - read_buf.filled().len()..poll_buf.pos]
			);
		}
		{
			assert_eq!(poll_buf.pos, 200);

			let mut buf = vec![0_u8; 100];
			let mut read_buf = ReadBuf::new(&mut buf);
			let is_empty = poll_buf.copy_to(&mut read_buf);

			assert!(is_empty);
			assert_eq!(read_buf.remaining(), 100 - 56);
			assert_eq!(poll_buf.pos, 256);
			assert_eq!(
				read_buf.filled(),
				&poll_buf.inner[poll_buf.pos - read_buf.filled().len()..poll_buf.pos]
			);
		}
	}
}
