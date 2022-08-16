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

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::{
	prelude::*,
	protocol::{inbound::HandshakeError, outbound::Error as OutboundError},
};
use std::{fmt::Display, io};

pub(super) const MAX_HEADERS_NUM: usize = 128;

pub(super) fn put_request_head<B: BufMut>(buf: &mut B, req: &http::Request<()>) {
	trace!("Putting request {:?} into buffer", req);
	// Beginning of line 0
	// Method
	buf.put(req.method().as_str().as_bytes());
	buf.put_u8(b' ');
	// Uri
	buf.put(req.uri().to_string().as_bytes());
	// Version
	buf.put_u8(b' ');
	buf.put(version_to_bytes(req.version()).unwrap_or_else(|| "".as_bytes()));
	// End of line 0
	buf.put(CRLF);

	// Multiple lines for request headers
	put_http_headers(buf, req.headers());

	// End of request head
	buf.put(CRLF);
}

pub(super) fn put_http_headers<B: BufMut>(buf: &mut B, headers: &http::HeaderMap) {
	// Each header field takes up one line
	for (name, value) in headers {
		// [name]: [value]
		buf.put_slice(name.as_str().as_bytes());
		buf.put_slice(&b": "[..]);
		buf.put_slice(value.as_bytes());
		buf.put_slice(CRLF);
	}
}

#[derive(Debug)]
pub(super) enum ReadError {
	Io(io::Error),
	Protocol(BoxStdErr),
	BadRequest(BoxStdErr),
	Partial,
}

impl Display for ReadError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "HTTP header ")?;
		match self {
			ReadError::Io(e) => {
				write!(f, "io error ({})", e)
			}
			ReadError::BadRequest(e) => {
				write!(f, "bad request ({})", e)
			}
			ReadError::Protocol(e) => {
				write!(f, "protocol error ({})", e)
			}
			ReadError::Partial => {
				write!(f, "is only partially in buffer")
			}
		}
	}
}

impl From<io::Error> for ReadError {
	fn from(e: io::Error) -> Self {
		ReadError::Io(e)
	}
}

impl StdErr for ReadError {}

fn find_pat(src: &[u8], pat: &[u8]) -> Option<usize> {
	if src.len() < pat.len() {
		return None;
	}
	src.windows(pat.len()).position(|window| window == pat)
}

pub(super) async fn read_until(
	mut r: impl AsyncBufRead + Unpin,
	pat: &[u8],
	dst: &mut [u8],
) -> io::Result<Option<usize>> {
	let mut pos = 0;
	assert!(pat.len() < dst.len());
	assert!(!pat.is_empty());

	while pos < dst.len() {
		let data = r.fill_buf().await?;
		println!("Get data ({} bytes)", data.len());
		// Reached EOF
		if data.is_empty() {
			return Err(io::ErrorKind::UnexpectedEof.into());
		}

		let rem = &mut dst[pos..];
		let copy_len = std::cmp::min(rem.len(), data.len());
		rem[..copy_len].copy_from_slice(&data[..copy_len]);

		let start_pos = pos.saturating_sub(pat.len());
		let curr_dst = &dst[start_pos..pos + copy_len];
		if let Some(pat_pos) = find_pat(curr_dst, pat) {
			let old_pos = pos;
			pos = start_pos + pat_pos + pat.len();
			r.consume(pos - old_pos);
			return Ok(Some(pos));
		}
		pos += copy_len;
		r.consume(copy_len);
	}
	Ok(None)
}

pub(super) fn get_version(ver: u8) -> Result<http::Version, ReadError> {
	Ok(match ver {
		1 => http::Version::HTTP_11,
		0 => http::Version::HTTP_10,
		_ => {
			let msg = format!("httparse version should only be 1 or 0, not {}", ver);
			return Err(ReadError::BadRequest(msg.into()));
		}
	})
}

pub(super) fn insert_headers(
	headers: &mut http::HeaderMap,
	parsed_headers: &[httparse::Header<'_>],
) -> Result<(), ReadError> {
	for header in parsed_headers {
		let key = http::header::HeaderName::from_str(header.name).map_err(|_| {
			ReadError::Protocol(format!("invalid header name {}", header.name).into())
		})?;
		let val = http::HeaderValue::from_bytes(header.value).map_err(|_| {
			ReadError::Protocol(format!("invalid header value {:?}", header.value).into())
		})?;
		headers.insert(key, val);
	}
	Ok(())
}

#[inline]
pub fn encode_auth(user: &str, pass: &str) -> String {
	base64::encode(format!("{}:{}", user, pass).as_bytes())
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
	#[error("HTTP authentication required but none provided")]
	EmptyAuthentication,
	#[error("HTTP authentication failed")]
	FailedAuthentication,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("HTTP protocol error ({0})")]
	FailedAuth(AuthError),
	#[error("HTTP protocol error (header too long)")]
	HeaderTooLong,
	#[error("HTTP protocol error (status code {0})")]
	WrongStatusCode(u16),
	#[error("HTTP protocol error (method {0} not supported)")]
	MethodNotAllow(String),
	#[error("HTTP protocol error (invalid HTTP header {0})")]
	InvalidHeader(BoxStdErr),
}

impl From<AuthError> for Error {
	#[inline]
	fn from(e: AuthError) -> Self {
		Error::FailedAuth(e)
	}
}

impl From<Error> for OutboundError {
	#[inline]
	fn from(e: Error) -> Self {
		OutboundError::Protocol(e.into())
	}
}

impl From<Error> for HandshakeError {
	#[inline]
	fn from(e: Error) -> Self {
		HandshakeError::Protocol(e.into())
	}
}

fn version_to_bytes(v: http::Version) -> Option<&'static [u8]> {
	Some(match v {
		http::Version::HTTP_09 => "HTTP/0.9".as_bytes(),
		http::Version::HTTP_10 => "HTTP/1.0".as_bytes(),
		http::Version::HTTP_11 => "HTTP/1.1".as_bytes(),
		http::Version::HTTP_2 => "HTTP/2".as_bytes(),
		http::Version::HTTP_3 => "HTTP/3".as_bytes(),
		_ => return None,
	})
}

#[cfg(test)]
mod tests {
	use tokio::io::{AsyncBufReadExt, BufReader};

	use super::*;

	#[test]
	fn test_encode_auth() {
		let data = [
			("hello", "world", "aGVsbG86d29ybGQ="),
			("world", "hello", "d29ybGQ6aGVsbG8="),
			("111111", "2222", "MTExMTExOjIyMjI="),
			("username", "password", "dXNlcm5hbWU6cGFzc3dvcmQ="),
		];
		for (username, password, expected) in &data {
			let result = encode_auth(username, password);
			assert_eq!(&result, expected);
		}
	}

	#[test]
	fn test_find_pat() {
		assert_eq!(find_pat(b"hello world!helloworld", b"hello"), Some(0));
		assert_eq!(find_pat(b"hello world!helloworld", b"world"), Some(6));
		assert_eq!(find_pat(b"hello world!helloworld", b"null"), None);
	}

	#[test]
	fn test_read_until() {
		let task = async move {
			let (r, mut w) = tokio::io::duplex(1024);
			let mut r = BufReader::new(r);
			let mut dst = [0u8; 256];
			w.write_all(b"HELLO WORLD\r\n\r\nextra").await.unwrap();
			let len = read_until(&mut r, b"\r\n\r\n", &mut dst)
				.await
				.unwrap()
				.unwrap();
			assert_eq!(&dst[..len], b"HELLO WORLD\r\n\r\n".as_ref());
			let remaining = r.fill_buf().await.unwrap();
			assert_eq!(remaining, b"extra");
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}

	#[test]
	fn test_read_until_steps() {
		let task = async move {
			let (r, mut w) = tokio::io::duplex(1024);
			let mut r = BufReader::new(r);
			let mut dst = [0u8; 256];

			let write_task = async move {
				w.write_all(b"HELLO WORLD").await.unwrap();
				w.write_all(b"\r\n").await.unwrap();
				w.write_all(b"\r\n").await.unwrap();
				w.write_all(b"extra").await.unwrap();
				w.shutdown().await.unwrap();
			};

			let read_task = async move {
				let len = read_until(&mut r, b"\r\n\r\n", &mut dst)
					.await
					.unwrap()
					.unwrap();
				assert_eq!(&dst[..len], b"HELLO WORLD\r\n\r\n".as_ref());
				let remaining = r.fill_buf().await.unwrap();
				assert_eq!(remaining, b"extra");
			};

			futures::future::join(write_task, read_task).await;
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}

	#[test]
	fn test_read_until_just_enough() {
		let task = async move {
			let (r, mut w) = tokio::io::duplex(1024);
			let mut r = BufReader::new(r);
			let mut dst = [0u8; 256];

			let write_task = async move {
				w.write_all(b"HELLO WORLD HELLO WORLD\r\n\r\n")
					.await
					.unwrap();
				w.shutdown().await.unwrap();
			};

			let read_task = async move {
				let len = read_until(&mut r, b"\r\n\r\n", &mut dst)
					.await
					.unwrap()
					.unwrap();
				assert_eq!(&dst[..len], b"HELLO WORLD HELLO WORLD\r\n\r\n".as_ref());
				let remaining = r.fill_buf().await.unwrap();
				assert_eq!(remaining, b"");
			};

			futures::future::join(write_task, read_task).await;
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}

	#[test]
	fn test_read_until_not_found() {
		println!("Testing not found");
		let task = async move {
			let (r, mut w) = tokio::io::duplex(1024);
			let mut r = BufReader::new(r);
			let mut dst = [0u8; 10];
			w.write_all(b"HELLO WORLD HELLO WORLD\r\n\r\n")
				.await
				.unwrap();
			w.shutdown().await.unwrap();
			let len = read_until(&mut r, b"\r\n\r\n", &mut dst).await.unwrap();
			assert_eq!(len, None);
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}

	#[test]
	fn test_read_until_fail_eof() {
		println!("Testing not found");
		let task = async move {
			let (r, mut w) = tokio::io::duplex(1024);
			let mut r = BufReader::new(r);
			let mut dst = [0u8; 256];
			w.write_all(b"HELLO WORLD\r\nextra").await.unwrap();
			w.shutdown().await.unwrap();
			let e = read_until(&mut r, b"\r\n\r\n", &mut dst).await.unwrap_err();
			assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}
}
