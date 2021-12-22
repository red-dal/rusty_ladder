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

pub use std::time::{SystemTime, UNIX_EPOCH};

use std::{convert::TryFrom, io};

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
