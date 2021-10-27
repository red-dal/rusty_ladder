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
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

pub type BoxRead = Box<dyn AsyncRead + Send + Sync + Unpin>;
pub type BoxWrite = Box<dyn AsyncWrite + Send + Sync + Unpin>;

pub struct ProxyStream {
	pub r: BoxRead,
	pub w: BoxWrite,
}

impl ProxyStream {
	#[inline]
	#[must_use]
	pub fn new(r: BoxRead, w: BoxWrite) -> Self {
		Self { r, w }
	}
}

impl From<(BoxRead, BoxWrite)> for ProxyStream {
	fn from((r, w): (BoxRead, BoxWrite)) -> Self {
		Self { r, w }
	}
}

impl AsyncRead for ProxyStream {
	#[inline]
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.get_mut().r).poll_read(cx, buf)
	}
}

impl AsyncWrite for ProxyStream {
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
	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		Pin::new(&mut self.get_mut().w).poll_shutdown(cx)
	}
}

impl From<tokio::net::TcpStream> for ProxyStream {
	fn from(val: tokio::net::TcpStream) -> Self {
		let (rh, wh) = val.into_split();
		ProxyStream::new(Box::new(rh), Box::new(wh))
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

pub trait GetProtocolName {
	fn protocol_name(&self) -> &'static str;
	fn network(&self) -> Network {
		Network::Tcp
	}
}
