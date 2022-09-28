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

#[cfg(feature = "async-tungstenite")]
pub mod websocket;

#[cfg(any(feature = "__crypto_openssl", feature = "__crypto_crypto_ring"))]
pub mod crypto;

#[cfg(feature = "__codec")]
pub mod codec;
pub mod relay;

#[cfg(any(feature = "__tls_rustls", feature = "__tls_openssl"))]
#[allow(dead_code)]
pub mod tls;

mod display_helper;
pub use display_helper::BytesCount;

#[allow(clippy::module_name_repetitions)]
mod poll;
pub use poll::{poll_read_exact, poll_write_all};

mod lazy_write_half;
pub use lazy_write_half::LazyWriteHalf;

mod one_or_more;
pub use one_or_more::OneOrMany;

use std::{
	convert::TryFrom,
	io,
	time::{SystemTime, UNIX_EPOCH},
};

#[allow(dead_code)]
#[inline]
pub fn timestamp_now() -> i64 {
	get_timestamp(SystemTime::now())
}

#[inline]
pub fn get_timestamp(time: SystemTime) -> i64 {
	let (neg, dur) = if let Ok(time) = time.duration_since(UNIX_EPOCH) {
		(false, time.as_secs())
	} else {
		(true, UNIX_EPOCH.duration_since(time).unwrap().as_secs())
	};
	let dur = i64::try_from(dur).unwrap();
	if neg {
		-dur
	} else {
		dur
	}
}

/// Append `val` in big endian after `buf` and return a mutable reference to the appended part.
///
/// Equals to `append_mut(buf, &val.to_be_bytes())`
#[allow(dead_code)]
pub(super) fn append_u16_mut(buf: &mut Vec<u8>, val: u16) -> &mut [u8] {
	append_mut(buf, &val.to_be_bytes())
}

/// Append `slice` after `buf` and return a mutable reference to the appended part.
#[allow(dead_code)]
pub(super) fn append_mut<'a>(buf: &'a mut Vec<u8>, slice: &[u8]) -> &'a mut [u8] {
	let pos = buf.len();
	buf.extend_from_slice(slice);
	&mut buf[pos..]
}

pub(crate) trait ReadInt: std::io::Read {
	/// Read a u8 from stream.
	///
	/// # Errors
	///
	/// Return the same error as `read_exact`.
	#[inline]
	fn read_u8(&mut self) -> io::Result<u8> {
		self.read_arr::<1>().map(|n| n[0])
	}

	/// Read a big endian u16 from stream.
	///
	/// # Errors
	///
	/// Return the same error as `read_exact`.
	#[inline]
	fn read_u16(&mut self) -> io::Result<u16> {
		self.read_arr::<2>().map(u16::from_be_bytes)
	}

	#[inline]
	fn read_arr<const N: usize>(&mut self) -> io::Result<[u8; N]> {
		let mut buf = [0_u8; N];
		self.read_exact(&mut buf).map(|_| buf)
	}
}

impl<T> ReadInt for T where T: std::io::Read {}

pub(crate) struct ListDisplay<'a, T>(pub &'a [T])
where
	T: std::fmt::Display;

impl<T> std::fmt::Display for ListDisplay<'_, T>
where
	T: std::fmt::Display,
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use std::fmt::Write;
		f.write_char('[')?;
		for (index, value) in self.0.iter().enumerate() {
			if index > 0 {
				f.write_str(", ")?;
			}
			value.fmt(f)?;
		}
		f.write_char(']')?;
		Ok(())
	}
}

#[cfg(feature = "parse-url")]
pub mod url {
	use crate::{prelude::BoxStdErr, protocol::SocksAddr};
	use url::Url;

	pub fn check_empty_path(url: &Url, _protocol_name: &str) -> Result<(), BoxStdErr> {
		if !url.path().is_empty() && url.path() != "/" {
			return Err("path must be empty".into());
		}
		Ok(())
	}

	pub fn check_scheme(url: &Url, protocol_name: &str) -> Result<(), BoxStdErr> {
		if url.scheme() != protocol_name {
			let msg = format!("expect scheme '{}', not '{}'", url.scheme(), protocol_name);
			return Err(msg.into());
		}
		Ok(())
	}

	#[allow(dead_code)]
	pub fn get_user_pass(url: &Url) -> Result<Option<(String, String)>, BoxStdErr> {
		Ok(
			if let Some((user, pass)) = url.password().map(|pass| (url.username(), pass)) {
				let user = percent_encoding::percent_decode_str(user)
					.decode_utf8()
					.map_err(|_| "cannot percent decode user part")?;
				let pass = percent_encoding::percent_decode_str(pass)
					.decode_utf8()
					.map_err(|_| "cannot percent decode password part")?;
				Some((user.into(), pass.into()))
			} else {
				None
			},
		)
	}

	#[allow(dead_code)]
	pub fn get_socks_addr(url: &Url, default_port: Option<u16>) -> Result<SocksAddr, BoxStdErr> {
		let host = url.host().ok_or("missing host")?;
		let port = if let Some(port) = url.port() {
			port
		} else if let Some(dp) = default_port {
			dp
		} else {
			return Err("missing port".into());
		};
		Ok(match host {
			url::Host::Domain(name) => SocksAddr::new(name.parse()?, port),
			url::Host::Ipv4(ip) => SocksAddr::new(ip.into(), port),
			url::Host::Ipv6(ip) => SocksAddr::new(ip.into(), port),
		})
	}
}

#[allow(dead_code)]
/// Format all items in "'first','second','third'...,'final'"
pub(crate) fn fmt_iter<T: std::fmt::Display>(
	f: &mut impl std::fmt::Write,
	mut items: impl Iterator<Item = T>,
) -> std::fmt::Result {
	if let Some(first) = items.next() {
		write!(f, "'{first}'")?;
		for item in items {
			write!(f, ",'{item}'")?;
		}
	}
	Ok(())
}

mod read_until {
	use std::io;
	use tokio::io::{AsyncBufRead, AsyncBufReadExt};

	fn find_pat(src: &[u8], pat: &[u8]) -> Option<usize> {
		if src.len() < pat.len() {
			return None;
		}
		src.windows(pat.len()).position(|window| window == pat)
	}

    #[allow(dead_code)]
	pub async fn read_until<'a>(
		mut r: impl AsyncBufRead + Unpin,
		pat: &[u8],
		dst: &'a mut [u8],
	) -> io::Result<Option<&'a [u8]>> {
		let mut pos = 0;
		assert!(pat.len() < dst.len());
		assert!(!pat.is_empty());

		while pos < dst.len() {
			let data = r.fill_buf().await?;
			// Reached EOF
			if data.is_empty() {
				return Err(io::ErrorKind::UnexpectedEof.into());
			}

			let dst_remaining = &mut dst[pos..];
			let copy_len = std::cmp::min(dst_remaining.len(), data.len());
			dst_remaining[..copy_len].copy_from_slice(&data[..copy_len]);

			let start_pos = pos.saturating_sub(pat.len());
			let curr_dst = &dst[start_pos..pos + copy_len];
			if let Some(pat_pos) = find_pat(curr_dst, pat) {
				let old_pos = pos;
				pos = start_pos + pat_pos + pat.len();
				r.consume(pos - old_pos);
				return Ok(Some(&dst[..pos]));
			}
			pos += copy_len;
			r.consume(copy_len);
		}
		Ok(None)
	}

	#[cfg(test)]
	mod tests {
		use super::*;
		use tokio::io::{AsyncWriteExt, BufReader};

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
				let buf = read_until(&mut r, b"\r\n\r\n", &mut dst)
					.await
					.unwrap()
					.unwrap();
				assert_eq!(buf, b"HELLO WORLD\r\n\r\n".as_ref());
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
					let buf = read_until(&mut r, b"\r\n\r\n", &mut dst)
						.await
						.unwrap()
						.unwrap();
					assert_eq!(buf, b"HELLO WORLD\r\n\r\n".as_ref());
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
					let buf = read_until(&mut r, b"\r\n\r\n", &mut dst)
						.await
						.unwrap()
						.unwrap();
					assert_eq!(buf, b"HELLO WORLD HELLO WORLD\r\n\r\n".as_ref());
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
}

#[allow(unused_imports)]
pub(super) use read_until::read_until;

mod chain_buf_read_half {
	use bytes::{Buf, Bytes};
	use std::{io, pin::Pin};
	use tokio::io::{AsyncBufRead, AsyncRead};

	/// HTTP read half.
	///
	/// Data in `buf` will be read first before polling `inner`.
	///
	/// This is used so ugly things like
	/// `Box::new(BufRead::new(io::chian(Cursor::new(buf), inner)))`
	/// can be avoided.
	pub struct ChainedReadHalf<R: AsyncBufRead + Unpin> {
		inner: R,
		buf: Option<Bytes>,
	}

	impl<R: AsyncBufRead + Unpin> ChainedReadHalf<R> {
        #[allow(dead_code)]
		pub fn new(inner: R, buf: impl Into<Bytes>) -> Self {
			Self {
				inner,
				buf: Some(buf.into()),
			}
		}
	}

	impl<R: AsyncBufRead + Unpin> AsyncRead for ChainedReadHalf<R> {
		fn poll_read(
			self: Pin<&mut Self>,
			cx: &mut std::task::Context<'_>,
			dst: &mut tokio::io::ReadBuf<'_>,
		) -> std::task::Poll<io::Result<()>> {
			let me = self.get_mut();
			if let Some(buf) = &mut me.buf {
				let len = std::cmp::min(buf.remaining(), dst.remaining());
				dst.put_slice(&buf[..len]);
				buf.advance(len);
				if buf.remaining() == 0 {
					me.buf = None;
				}
				Ok(()).into()
			} else {
				Pin::new(&mut me.inner).poll_read(cx, dst)
			}
		}
	}

	impl<R: AsyncBufRead + Unpin> AsyncBufRead for ChainedReadHalf<R> {
		fn poll_fill_buf(
			self: Pin<&mut Self>,
			cx: &mut std::task::Context<'_>,
		) -> std::task::Poll<io::Result<&[u8]>> {
			let me = self.get_mut();
			if let Some(buf) = &me.buf {
				Ok(buf.chunk()).into()
			} else {
				Pin::new(&mut me.inner).poll_fill_buf(cx)
			}
		}

		fn consume(self: Pin<&mut Self>, amt: usize) {
			let me = self.get_mut();
			if let Some(buf) = &mut me.buf {
				buf.advance(amt);
				if buf.remaining() == 0 {
					me.buf = None;
				}
			} else {
				Pin::new(&mut me.inner).consume(amt);
			}
		}
	}
}

pub use chain_buf_read_half::ChainedReadHalf;
