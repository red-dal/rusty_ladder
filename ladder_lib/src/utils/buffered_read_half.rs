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

use crate::{prelude::*, utils::PollBuffer};
use std::{
	io,
	task::{Context, Poll},
};
use tokio::io::ReadBuf;

pub struct BufferedReadHalf<R: AsyncRead + Unpin> {
	read_half: R,
	data: Option<PollBuffer>,
}

impl<R: AsyncRead + Unpin> BufferedReadHalf<R> {
	#[allow(dead_code)]
	pub fn new(read_half: R, data: Vec<u8>) -> Self {
		let data = if data.is_empty() {
			None
		} else {
			Some(PollBuffer::new(data))
		};
		Self { read_half, data }
	}
}

impl<R: AsyncRead + Unpin> AsyncRead for BufferedReadHalf<R> {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		dst_buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let me = self.get_mut();
		#[allow(clippy::option_if_let_else)]
		if let Some(src_data) = &mut me.data {
			if src_data.copy_to(dst_buf) {
				me.data = None;
			}
			Ok(()).into()
		} else {
			Pin::new(&mut me.read_half).poll_read(cx, dst_buf)
		}
	}
}
