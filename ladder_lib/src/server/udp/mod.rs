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

mod connection_map;

use super::Error;
use crate::{
	prelude::*,
	protocol::{
		inbound::udp::{PacketStream, Session},
		outbound::{
			udp::{Connector, GetConnector, SocketOrTunnelStream},
			Error as OutboundError,
		},
		ProxyContext,
	},
	server::stat::{Id, RegisterArgs},
	Monitor,
};
use bytes::{Bytes, BytesMut};
use connection_map::ConnectionsMap;
use futures::{channel::mpsc, future::Either, Future, FutureExt, SinkExt, StreamExt};
use std::{
	io,
	time::{Duration, SystemTime},
};

type ArcMutex<T> = Arc<AsyncMutex<T>>;
pub type DataReceiver = mpsc::Receiver<(Session, Bytes)>;
pub type DataSender = mpsc::Sender<(Session, Bytes)>;

/// Interval between checking timeout status.
const TIMEOUT_GUARD_INTERVAL: Duration = Duration::from_millis(1000);
const TASK_TIMEOUT: Duration = Duration::from_millis(200);
const UDP_BUFFER_SIZE: usize = 8 * 1024;
const UDP_PACKET_BUFFER_SIZE: usize = 64;
/// Udp socket/tunnel will be dropped if there is no read or write for more than
/// this duration.
const UDP_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

pub async fn dispatch(
	stream: PacketStream,
	inbound: &super::Inbound,
	inbound_ind: usize,
	inbound_bind_addr: SocketAddr,
	server: &super::Server,
	monitor: Option<Monitor>,
) -> Result<(), Error> {
	trace!(
		"Dispatching UDP packet for inbound[{}] on {}",
		inbound_ind,
		inbound_bind_addr
	);
	let (mut read_half, mut write_half) = (stream.read_half, stream.write_half);
	let (inbound_sender, mut inbound_receiver) = mpsc::channel(UDP_PACKET_BUFFER_SIZE);

	let (dispatcher, guard_task) = Dispatcher::new(inbound.tag.clone(), inbound_sender, monitor);

	// Read data from inbound, and send to outbound
	let send_task = async move {
		loop {
			let mut data = BytesMut::new();
			data.resize(UDP_BUFFER_SIZE, 0);

			let in_res = read_half.recv_inbound(&mut data).await?;
			data.truncate(in_res.len);
			if data.is_empty() {
				trace!("Done receiving UDP packet");
				break;
			}

			let src = in_res.src.unwrap_or(inbound_bind_addr);
			let dst = in_res.dst;

			trace!(
				"UDP packet sent ({} bytes) from {} (client) to {} (server)",
				data.len(),
				src,
				dst
			);

			let session = Session {
				src,
				dst: dst.clone(),
			};

			if let Err(e) = dispatcher
				.send(&session, data.freeze(), inbound_ind, server)
				.await
			{
				error!(
					"Error occurred when sending UDP packet from '{}' to '{}': {}",
					src, dst, e
				);
				// TODO: Maybe more error handling, like retry
			}
		}

		Result::<(), io::Error>::Ok(())
	};

	// Receive data from outbound, and write to inbound
	let recv_task = async move {
		while let Some((sess, data)) = inbound_receiver.next().await {
			trace!(
				"UDP packet received ({} bytes) from {} (server) to {} (client)",
				data.len(),
				sess.dst,
				sess.src
			);
			write_half.send_inbound(&sess, &data).await?;
		}
		Result::<(), io::Error>::Ok(())
	};

	futures::pin_mut!(send_task);
	futures::pin_mut!(recv_task);
	let proxy_task = select_timeout(TASK_TIMEOUT, send_task, recv_task).map(|result| {
		match result {
			SelectResult::Left(lr) => {
				trace!("recv_task timeout");
				lr?;
			}
			SelectResult::Right(rr) => {
				trace!("send_task timeout");
				rr?;
			}
			SelectResult::Both((lr, rr)) => {
				trace!("UDP send_task and recv_task completed");
				lr?;
				rr?;
			}
		}
		Result::<(), Error>::Ok(())
	});

	let guard_task = guard_task.map(|_| Result::<(), Error>::Ok(()));

	futures::try_join!(proxy_task, guard_task).map(|_| ())
}

struct Dispatcher {
	inbound_tag: Tag,
	inbound_sender: DataSender,
	map: ConnectionsMap,
	monitor: Option<Monitor>,
}

impl Dispatcher {
	pub fn new(
		inbound_tag: Tag,
		inbound_sender: DataSender,
		monitor: Option<Monitor>,
	) -> (Self, impl Future<Output = ()>) {
		let (map, guard_task) = ConnectionsMap::new();
		(
			Self {
				inbound_tag,
				inbound_sender,
				map,
				monitor,
			},
			guard_task,
		)
	}

	pub async fn send(
		&self,
		sess: &Session,
		data: Bytes,
		inbound_ind: usize,
		server: &super::Server,
	) -> Result<(), Error> {
		trace!(
			"Dispatcher sending packet for session ({} -> {})",
			sess.src,
			sess.dst
		);
		let (outbound, outbound_ind) = server
			.router
			.choose_outbound(inbound_ind, &sess.src, &sess.dst)
			.map(|ind| (&server.outbounds[ind], ind))
			.ok_or(OutboundError::NotAllowed)?;

		let mut outbound_sender: DataSender =
			if let Some(outbound_sender) = self.map.get(sess, outbound_ind).await {
				trace!(
					"Outbound sender found for session ({} -> {})",
					sess.src,
					sess.dst
				);
				// Session tunnel already exists.
				// Use the sender to send data to outbound
				outbound_sender
			} else {
				trace!(
					"Creating sender and tasks for session ({} -> {})",
					sess.src,
					sess.dst
				);
				// Session tunnel not exists, create one
				let sess_id = rand::random::<Id>();

				let sess_handle = self.monitor.as_ref().map(|m| {
					let h = m.register_udp_session(RegisterArgs {
						conn_id: sess_id,
						inbound_ind,
						inbound_tag: self.inbound_tag.clone(),
						start_time: SystemTime::now(),
						from: sess.src,
					});
					h.set_connecting(outbound_ind, outbound.tag.clone(), sess.dst.clone());
					h
				});
				let result = {
					let sess_handle = sess_handle.as_ref();
					async move {
						let stream = connect_outbound(sess, &outbound.settings, server).await?;
						self.map
							.register_session(
								self.inbound_sender.clone(),
								sess,
								sess_handle,
								outbound_ind,
								stream,
							)
							.await
					}
					.await
				};
				match result {
					Ok(r) => r,
					Err(e) => {
						if let Some(h) = sess_handle {
							h.set_dead(SystemTime::now());
						}
						return Err(e);
					}
				}
			};
		if let Err(e) = outbound_sender.send((sess.clone(), data)).await {
			debug!(
				"Cannot send data for session ('{}' -> '{}'): {} ",
				sess.src, sess.dst, e
			);
			// Normally when connection drop, the sender will also be removed from TunnelMap.

			// TODO: More error handling, like creating tunnel again
		}
		Ok(())
	}
}

async fn connect_outbound<C>(
	sess: &Session,
	outbound: &C,
	ctx: &dyn ProxyContext,
) -> Result<SocketOrTunnelStream, OutboundError>
where
	C: GetConnector + Send + Sync,
{
	let connector = outbound
		.get_udp_connector()
		.ok_or(OutboundError::UdpNotSupported)?;
	let stream = match connector {
		Connector::Socket(c) => c.connect_socket(ctx).await,
		Connector::SocketOverTcp(c) => c.connect(ctx).await,
		Connector::Tunnel(c) => c.connect_tunnel(&sess.dst, ctx).await,
		Connector::TunnelOverTcp(c) => c.connect(&sess.dst, ctx).await,
	}?;
	Ok(stream)
}

/// Polls two futures simutaniously.
///
/// If one of the future completed, the other future will still be polled until timeout in `dur`.
async fn select_timeout<V, E>(
	dur: Duration,
	fut_a: impl Future<Output = Result<V, E>> + Unpin,
	fut_b: impl Future<Output = Result<V, E>> + Unpin,
) -> SelectResult<Result<V, E>> {
	match futures::future::select(fut_a, fut_b).await {
		Either::Left((left_res, right_fut)) => {
			// Poll right_fut with a timeout
			match tokio::time::timeout(dur, right_fut).await {
				Ok(right_res) => SelectResult::Both((left_res, right_res)),
				Err(_) => SelectResult::Left(left_res),
			}
		}
		Either::Right((right_res, left_fut)) => {
			// Same as above
			match tokio::time::timeout(dur, left_fut).await {
				Ok(left_res) => SelectResult::Both((left_res, right_res)),
				Err(_) => SelectResult::Right(right_res),
			}
		}
	}
}

enum SelectResult<T> {
	Left(T),
	Right(T),
	Both((T, T)),
}
