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

mod atomic_values;
mod stream_copier;

pub use atomic_values::Counter;

use crate::prelude::*;
use atomic_values::Switch;
use futures::{
	future::{self, Either},
	Future, FutureExt,
};
use std::{io, time::Duration};
use stream_copier::StreamCopier;
use tokio::time::timeout;

const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;
const OTHER_TASK_TIMEOUT: Duration = Duration::from_millis(2000);

const STOPPED: bool = true;
const NOT_STOPPED: bool = !STOPPED;

const ACTIVE: bool = true;
const NOT_ACTIVE: bool = !ACTIVE;

const TICK_INTERVAL: Duration = Duration::from_secs(1);
const MAX_TICK_NUM: usize = 300;

pub struct Relay<'a> {
	pub conn_id: &'a str,
	pub recv: Option<Counter>,
	pub send: Option<Counter>,
	pub buffer_size: usize,
}

impl<'a> Relay<'a> {
	#[inline]
	pub fn new(conn_id: &'a str) -> Self {
		Self {
			conn_id,
			recv: None,
			send: None,
			buffer_size: DEFAULT_BUFFER_SIZE,
		}
	}

	#[inline]
	pub fn set_recv(&mut self, recv: Counter) -> &mut Self {
		self.recv = Some(recv);
		self
	}

	/// Set send counter.
	#[inline]
	pub fn set_send(&mut self, send: Counter) -> &mut Self {
		self.send = Some(send);
		self
	}

	/// Set the size of the buffer.
	///
	/// Two buffers will be used during relay (send and receive).
	#[inline]
	pub fn set_buffer_size(&mut self, size: usize) -> &mut Self {
		self.buffer_size = size;
		self
	}
}

impl Default for Relay<'static> {
	#[inline]
	fn default() -> Self {
		Self::new("")
	}
}

impl Relay<'_> {
	pub async fn relay_stream<IR, IW, OR, OW>(
		&self,
		ir: IR,
		iw: IW,
		or: OR,
		ow: OW,
	) -> io::Result<(IR, IW, OR, OW)>
	where
		IR: AsyncRead + Unpin + Send + 'static,
		OR: AsyncRead + Unpin + Send + 'static,
		IW: AsyncWrite + Unpin + Send + 'static,
		OW: AsyncWrite + Unpin + Send + 'static,
	{
		let send_tag = Arc::<str>::from(format!("[{} send]", self.conn_id));
		let recv_tag = Arc::<str>::from(format!("[{} recv]", self.conn_id));

		let recv = self.recv.clone().unwrap_or_else(|| Counter::new(0));
		let send = self.send.clone().unwrap_or_else(|| Counter::new(0));

		let is_stopped = Switch::new(NOT_STOPPED);
		let is_active = Switch::new(NOT_ACTIVE);

		// Inbound <--- Outbound
		// Read from outbound and write to inbound
		let recv_task = StreamCopier {
			r: or,
			w: iw,
			count: recv,
			tag: recv_tag.clone(),
			is_reading_stopped: is_stopped.clone(),
			buffer_size: self.buffer_size,
			is_active: is_active.clone(),
		}
		.run();
		// Inbound ---> Outbound
		// Read from inbound and write to outbound
		let send_task = StreamCopier {
			r: ir,
			w: ow,
			count: send,
			tag: send_tag.clone(),
			is_reading_stopped: is_stopped.clone(),
			buffer_size: self.buffer_size,
			is_active: is_active.clone(),
		}
		.run();

		let guard_task = guard_is_active(is_active).map(|_| {
			Err::<(IR, IW, OR, OW), _>(io::Error::new(
				io::ErrorKind::TimedOut,
				"connection not active for too long",
			))
		});

		let relay_task = async move {
			futures::pin_mut!(recv_task);
			futures::pin_mut!(send_task);
			match future::select(recv_task, send_task).await {
				Either::Left(((or, iw, recv_res), send_task)) => {
					trace!("{} task finished", recv_tag);
					let (ir, ow) = handle_other_task(recv_res, &send_tag, send_task).await?;
					Ok((ir, iw, or, ow))
				}
				Either::Right(((ir, ow, send_res), recv_task)) => {
					trace!("{} task finished", send_tag);
					let (or, iw) = handle_other_task(send_res, &recv_tag, recv_task).await?;
					Ok((ir, iw, or, ow))
				}
			}
		};

		futures::pin_mut!(guard_task);
		futures::pin_mut!(relay_task);

		#[allow(clippy::mut_mut)]
		{
			futures::select! {
				res = guard_task.fuse() => res,
				res = relay_task.fuse() => res,
			}
		}
	}
}

async fn handle_other_task<F, R, W>(
	curr_res: io::Result<()>,
	tag: &str,
	task: Pin<&mut F>,
) -> io::Result<(R, W)>
where
	F: Future<Output = (R, W, io::Result<()>)>,
	R: 'static + AsyncRead + Unpin,
	W: 'static + AsyncWrite + Unpin,
{
	// Current task completes beore send task.
	// So this should be ok to ignore.
	if let Err(err) = curr_res {
		debug!("{} task error ({})", tag, err);
	}
	// Wait for send task to complete.
	// Set a timeout so that send half won't hang forever.
	let (r, w, res) = match timeout(OTHER_TASK_TIMEOUT, task).await {
		Ok(r) => r,
		Err(err) => {
			debug!(
				"{} Cannot finish shutdown task in {} ms ({})",
				tag,
				OTHER_TASK_TIMEOUT.as_millis(),
				err
			);
			return Err(io::Error::new(io::ErrorKind::Other, err));
		}
	};
	if let Err(err) = res {
		debug!(
			"{} task error ({}), but ignored since the connection is closed.",
			tag, err
		);
	}
	Ok((r, w))
}

async fn guard_is_active(is_active: Switch) {
	let mut last_tick_count = 0_usize;
	loop {
		tokio::time::sleep(TICK_INTERVAL).await;
		let last_is_active = is_active.fetch_and_set(NOT_ACTIVE);
		if last_is_active == ACTIVE {
			last_tick_count = 0;
		} else {
			last_tick_count += 1;
			if last_tick_count >= MAX_TICK_NUM {
				break;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Cursor;

	#[test]
	fn test_relay_stream() {
		// in_data  -> in_result
		// out_data -> out_result
		let mut in_data = vec![0_u8; 64];
		for i in 0..in_data.len() {
			in_data[i] = i as u8;
		}
		let mut out_data = vec![0_u8; 128];
		for i in 0..out_data.len() {
			out_data[i] = (i + in_data.len()) as u8;
		}

		let in_result = vec![0_u8; out_data.len()];
		let out_result = vec![0_u8; in_data.len()];

		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			let in_reader = Cursor::new(in_data);
			let in_writer = Cursor::new(in_result);
			let out_reader = Cursor::new(out_data);
			let out_writer = Cursor::new(out_result);

			let recv = Counter::new(0);
			let send = Counter::new(0);

			let res = Relay::default()
				.set_recv(recv.clone())
				.set_send(send.clone())
				.relay_stream(in_reader, in_writer, out_reader, out_writer)
				.await;
			let (in_reader, in_writer, out_reader, out_writer) = res.unwrap();

			let in_data = in_reader.into_inner();
			let out_data = out_reader.into_inner();
			let in_result = in_writer.into_inner();
			let out_result = out_writer.into_inner();

			assert_eq!(send.get(), in_data.len() as u64);
			assert_eq!(recv.get(), out_data.len() as u64);

			assert_eq!(&in_data, &out_result);
			assert_eq!(&out_data, &in_result);
		});
	}
}
