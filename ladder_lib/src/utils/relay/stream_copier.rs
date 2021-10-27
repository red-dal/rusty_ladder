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

use super::{
	atomic_values::{Counter, Switch},
	STOPPED, ACTIVE
};
use crate::prelude::*;
use std::io;

/// Copy bytes from `r` to `w`.
pub(super) struct StreamCopier<R, W>
where
	R: AsyncRead + Unpin + Send + 'static,
	W: AsyncWrite + Unpin + Send + 'static,
{
	pub r: R,
	pub w: W,
	pub count: Counter,
	pub tag: Arc<str>,
	pub is_reading_stopped: Switch,
	pub buffer_size: usize,
	pub is_active: Switch,
}

impl<R, W> StreamCopier<R, W>
where
	R: AsyncRead + Unpin + Send + 'static,
	W: AsyncWrite + Unpin + Send + 'static,
{
	pub async fn run(mut self) -> (R, W, io::Result<()>) {
		let mut buffer = vec![0_u8; self.buffer_size];
		loop {
			trace!("{} Reading from read_half...", self.tag);
			let n = match self.r.read(&mut buffer).await {
				Ok(res) => res,
				Err(err) => return (self.r, self.w, Err(err)),
			};
			trace!("{} Done reading from read_half, n: {}", self.tag, n);
			self.is_active.set(ACTIVE);

			if n == 0 {
				debug!(
					"{} read_half reach EOF, shutting down write_half.",
					self.tag
				);
				self.is_reading_stopped.set(STOPPED);
				let res = if let Err(err) = self.w.shutdown().await {
					debug!(
						"{} Error when trying to shutdown write_half ({})",
						self.tag, err
					);
					Err(err)
				} else {
					Ok(())
				};
				return (self.r, self.w, res);
			}

			let data = &buffer[..n];
			debug_assert!(!data.is_empty());

			let mut pos: usize = 0;
			while pos < data.len() {
				trace!("{} Writing into write_half...", self.tag);
				let n = match self.w.write(&data[pos..]).await {
					Ok(n) => n,
					Err(err) => {
						let res = if self.is_reading_stopped.get() == STOPPED {
							debug!("{} Error occurred when trying to write data to write_half ({}), but ignored because other read_half is stopped", self.tag, err);
							Ok(())
						} else {
							debug!(
								"{} Error occurred when trying to write data to write_half ({})",
								self.tag, err
							);
							Err(err)
						};
						return (self.r, self.w, res);
					}
				};
				trace!("{} Done writing into write_half, n: {}", self.tag, n);
				self.is_active.set(ACTIVE);
				if n == 0 {
					return (self.r, self.w, Err(io::ErrorKind::WriteZero.into()));
				}
				pos += n;
				self.count.add(n as u64);
			}
		}
	}
}
