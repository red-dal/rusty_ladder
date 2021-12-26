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
	ACTIVE, STOPPED,
};
use crate::prelude::*;
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Copy bytes from `r` to `w`.
pub(super) struct StreamCopier<R, W>
where
	R: AsyncBufRead + Unpin + Send + 'static,
	W: AsyncWrite + Unpin + Send + 'static,
{
	pub r: R,
	pub w: W,
	pub count: Counter,
	pub tag: Arc<str>,
	pub is_reading_stopped: Switch,
	pub is_active: Switch,
}

impl<R, W> StreamCopier<R, W>
where
	R: AsyncBufRead + Unpin + Send + 'static,
	W: AsyncWrite + Unpin + Send + 'static,
{
	pub async fn run(mut self) -> (R, W, io::Result<()>) {
		loop {
			trace!("{} Filling read_half's internal buffer...", self.tag);
			let data = match self.r.fill_buf().await {
				Ok(res) => res,
				Err(err) => return (self.r, self.w, Err(err)),
			};
			trace!(
				"{} Done filling read_half, data.len(): {}",
				self.tag,
				data.len()
			);
			self.is_active.set(ACTIVE);

			if data.is_empty() {
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

			debug_assert!(!data.is_empty());

			trace!("{} Writing into write_half...", self.tag);
			let write_amt = match self.w.write(data).await {
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
			trace!("{} Done writing into write_half, write_amt: {}", self.tag, write_amt);
			if write_amt == 0 {
				return (self.r, self.w, Err(io::ErrorKind::WriteZero.into()));
			}
			self.is_active.set(ACTIVE);
			// Advance the buffer position in self.r
			self.r.consume(write_amt);
			// Update traffic counter
			self.count.add(write_amt as u64);
		}
	}
}
