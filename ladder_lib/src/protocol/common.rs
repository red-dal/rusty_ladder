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

use crate::prelude::*;
use std::{
	io,
	task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

pub type BoxRead = Box<dyn AsyncRead + Send + Sync + Unpin>;
pub type BoxBufRead = Box<dyn AsyncBufRead + Send + Sync + Unpin>;
pub type BoxWrite = Box<dyn AsyncWrite + Send + Sync + Unpin>;

macro_rules! impl_inner_read {
	() => {
		#[inline]
		fn poll_read(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
			buf: &mut ReadBuf<'_>,
		) -> Poll<std::io::Result<()>> {
			Pin::new(&mut self.get_mut().r).poll_read(cx, buf)
		}
	};
}

macro_rules! impl_inner_write {
	() => {
		#[inline]
		fn poll_write(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
			buf: &[u8],
		) -> Poll<Result<usize, io::Error>> {
			Pin::new(&mut self.get_mut().w).poll_write(cx, buf)
		}

		#[inline]
		fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
			Pin::new(&mut self.get_mut().w).poll_flush(cx)
		}

		#[inline]
		fn poll_shutdown(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
		) -> Poll<Result<(), io::Error>> {
			Pin::new(&mut self.get_mut().w).poll_shutdown(cx)
		}
	};
}

macro_rules! impl_inner_buf_read {
	() => {
		fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
			Pin::new(&mut self.get_mut().r).poll_fill_buf(cx)
		}

		fn consume(self: Pin<&mut Self>, amt: usize) {
			Pin::new(&mut self.get_mut().r).consume(amt)
		}
	};
}
// --------------------------------------------
//                AsyncReadWrite
// --------------------------------------------

pub trait AsyncReadWrite: 'static + AsyncRead + AsyncWrite + Send + Sync + Unpin {
	fn split(self: Box<Self>) -> (BoxRead, BoxWrite);
}

impl AsyncReadWrite for tokio::net::TcpStream {
	fn split(self: Box<Self>) -> (BoxRead, BoxWrite) {
		let (r, w) = self.into_split();
		(Box::new(r), Box::new(w))
	}
}

#[cfg(unix)]
impl AsyncReadWrite for tokio::net::UnixStream {
	fn split(self: Box<Self>) -> (BoxRead, BoxWrite) {
		let (rh, wh) = self.into_split();
		(Box::new(rh), Box::new(wh))
	}
}

impl From<tokio::net::TcpStream> for Box<dyn AsyncReadWrite> {
	fn from(stream: tokio::net::TcpStream) -> Self {
		Box::new(stream)
	}
}

// --------------------------------------------
//             CompositeBytesStream
// --------------------------------------------

pub struct CompositeBytesStream<R, W>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	pub r: R,
	pub w: W,
}

impl<R, W> CompositeBytesStream<R, W>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	#[inline]
	#[must_use]
	pub fn new(r: R, w: W) -> Self {
		Self { r, w }
	}
}

impl<R, W> AsyncRead for CompositeBytesStream<R, W>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	impl_inner_read!();
}
impl<R, W> AsyncBufRead for CompositeBytesStream<R, W>
where
	R: AsyncBufRead + Unpin,
	W: AsyncWrite + Unpin,
{
	impl_inner_buf_read!();
}

impl<R, W> AsyncWrite for CompositeBytesStream<R, W>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	impl_inner_write!();
}

impl<R, W> AsyncReadWrite for CompositeBytesStream<R, W>
where
	R: 'static + AsyncRead + Unpin + Send + Sync,
	W: 'static + AsyncWrite + Unpin + Send + Sync,
{
	fn split(self: Box<Self>) -> (BoxRead, BoxWrite) {
		(Box::new(self.r), Box::new(self.w))
	}
}

// --------------------------------------------
//               BufBytesStream
// --------------------------------------------

pub struct BufBytesStream {
	pub r: BoxBufRead,
	pub w: BoxWrite,
}

impl BufBytesStream {
	#[must_use]
	#[inline]
	pub fn new(r: BoxBufRead, w: BoxWrite) -> Self {
		// TODO: use with_capacity instead of default capacity
		Self { r, w }
	}
}

impl AsyncRead for BufBytesStream {
	impl_inner_read!();
}

impl AsyncWrite for BufBytesStream {
	impl_inner_write!();
}

impl AsyncBufRead for BufBytesStream {
	impl_inner_buf_read!();
}

impl From<tokio::net::TcpStream> for BufBytesStream {
	fn from(val: tokio::net::TcpStream) -> Self {
		let (r, w) = val.into_split();
		let r = tokio::io::BufReader::new(r);
		BufBytesStream {
			r: Box::new(r),
			w: Box::new(w),
		}
	}
}

impl From<Box<dyn AsyncReadWrite>> for BufBytesStream {
	fn from(s: Box<dyn AsyncReadWrite>) -> Self {
		let (rh, wh) = s.split();
		Self::new(Box::new(tokio::io::BufReader::new(rh)), wh)
	}
}

impl AsyncReadWrite for BufBytesStream {
	fn split(self: Box<Self>) -> (BoxRead, BoxWrite) {
		(Box::new(self.r), self.w)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub enum Network {
	#[cfg_attr(feature = "use_serde", serde(rename = "tcp"))]
	Tcp,
	#[cfg_attr(feature = "use_serde", serde(rename = "udp"))]
	Udp,
	#[cfg_attr(feature = "use_serde", serde(rename = "tcp_udp"))]
	TcpAndUdp,
}

impl Network {
	#[inline]
	#[must_use]
	pub fn use_tcp(self) -> bool {
		matches!(self, Network::Tcp | Network::TcpAndUdp)
	}

	#[inline]
	#[must_use]
	pub fn use_udp(self) -> bool {
		matches!(self, Network::Udp | Network::TcpAndUdp)
	}
}

impl Default for Network {
	#[inline]
	fn default() -> Self {
		Network::Tcp
	}
}

pub trait GetProtocolName {
	fn protocol_name(&self) -> &'static str;
	fn network(&self) -> Network {
		Network::Tcp
	}
}

// --------------------------------------------
//                    Info
// --------------------------------------------

pub struct BriefHelper<'a, T: ?Sized + DisplayInfo>(&'a T);

impl<T: DisplayInfo> std::fmt::Display for BriefHelper<'_, T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt_brief(f)
	}
}

pub struct DetailHelper<'a, T: ?Sized + DisplayInfo>(&'a T);

impl<T: DisplayInfo> std::fmt::Display for DetailHelper<'_, T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt_detail(f)
	}
}

pub trait DisplayInfo {
	/// Format some brief info.
	///
	/// # Errors
	/// See more at [`std::fmt::Display`]
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
	/// Format some detail info.
	///
	/// # Errors
	/// See more at [`std::fmt::Display`]
	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
	fn brief(&self) -> BriefHelper<'_, Self> {
		BriefHelper(self)
	}
	fn detail(&self) -> DetailHelper<'_, Self> {
		DetailHelper(self)
	}
}
