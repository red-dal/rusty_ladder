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
	select_timeout, ArcMutex, DataReceiver, DataSender, Error, TASK_TIMEOUT,
	TIMEOUT_GUARD_INTERVAL, UDP_BUFFER_SIZE, UDP_PACKET_BUFFER_SIZE, UDP_TIMEOUT_DURATION,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::udp::Session,
		outbound::udp::{socket, tunnel, SocketOrTunnelStream},
	},
};
use bytes::BytesMut;
use futures::{channel::mpsc, Future, SinkExt, StreamExt};
use std::{
	collections::HashMap,
	io,
	sync::atomic::{AtomicBool, Ordering},
	time::{Duration, Instant},
};
use tokio::task::JoinHandle;

const STOPPED: bool = true;
const NOT_STOPPED: bool = !STOPPED;

/// A map that stores outbound senders of every sessions.
///
/// In order to send data to outbound, you need to get a sender from this map.
///
/// For every tunnel, there can be only one session.
/// But for every socket, there can be multiple sessions.
pub(super) struct ConnectionsMap {
	/// (Source address, OutboundId) -> DataSender
	sockets: ArcMutex<SocketsMap>,
	/// Session -> DataSender
	///
	/// This assumes that one session can only use one outbound.
	tunnels: ArcMutex<TunnelsMap>,
	stopped: Arc<AtomicBool>,
}

impl Drop for ConnectionsMap {
	fn drop(&mut self) {
		// Start gracefully shutdown
		self.stopped.store(STOPPED, Ordering::Relaxed);
	}
}

impl ConnectionsMap {
	pub fn new() -> (Self, impl Future<Output = ()>) {
		let stopped = Arc::new(AtomicBool::new(NOT_STOPPED));
		let sockets = Arc::new(AsyncMutex::new(SocketsMap::default()));
		let tunnels = Arc::new(AsyncMutex::new(TunnelsMap::default()));
		// Guard task clean up any session that hasn't been used for a while.
		let guard_task = {
			let sockets = sockets.clone();
			let tunnels = tunnels.clone();
			let stopped = stopped.clone();
			async move {
				loop {
					if stopped.load(Ordering::Relaxed) == STOPPED {
						break;
					}
					tokio::time::sleep(TIMEOUT_GUARD_INTERVAL).await;

					// Lock both mutexes before removing anything
					let mut sockets = sockets.lock().await;
					let mut tunnels = tunnels.lock().await;
					let now = Instant::now();

					// Find timeout sessions
					let mut timeout_sockets = Vec::new();
					for (key, conn) in &sockets.map {
						if conn.check_timeout(now, UDP_TIMEOUT_DURATION).await {
							debug!(
								"UDP socket for (src {}, outbound_ind {}) is outdated",
								key.0, key.1
							);
							timeout_sockets.push(*key);
						}
					}
					let mut timeout_tunnels = Vec::new();
					for (key, conn) in &tunnels.map {
						if conn.check_outdated(now, UDP_TIMEOUT_DURATION).await {
							debug!(
								"UDP tunnel for src {}, dst {} is outdated",
								key.src, key.dst
							);
							timeout_tunnels.push(key.clone());
						}
					}

					// Remove timeout sessions from map
					for (src, outbound_ind) in timeout_sockets {
						sockets.remove(src, outbound_ind);
					}
					for sess in timeout_tunnels {
						tunnels.remove(&sess);
					}
				}
				// Gracefully shutdown
				debug!("Shutting down ConnectionMap guard task. Clean up all connections");
				sockets.lock().await.remove_all();
				tunnels.lock().await.remove_all();
			}
		};
		(
			Self {
				sockets,
				tunnels,
				stopped,
			},
			guard_task,
		)
	}

	/// Get data sender for `session`.
	///
	/// Returns `None` if there are no tunnels ready for this session and no sockets running.
	pub async fn get(&self, session: &Session, outbound_ind: usize) -> Option<DataSender> {
		if let Some(s) = self.sockets.lock().await.get(session.src, outbound_ind) {
			return Some(s.sender.clone());
		} else if let Some(t) = self.tunnels.lock().await.get(session) {
			return Some(t.sender.clone());
		}
		None
	}

	pub async fn create_connection(
		&self,
		inbound_sender: DataSender,
		sess: &Session,
		outbound_ind: usize,
		stream: SocketOrTunnelStream,
	) -> Result<DataSender, Error> {
		// Make sure that sender does not exists
		{
			let mut contains_key = self
				.sockets
				.lock()
				.await
				.get(sess.src, outbound_ind)
				.is_some();

			if !contains_key && self.tunnels.lock().await.get(sess).is_some() {
				contains_key = true;
			}

			if contains_key {
				let msg = format!(
					"sender for session src '{}' dst '{}' and outbound_ind {} already exists",
					sess.src, sess.dst, outbound_ind
				);
				return Err(Error::Io(io::Error::new(io::ErrorKind::Other, msg)));
			}
		}

		// Anything sent from this sender will be written into outbound stream.
		let (outbound_sender, outbound_receiver) = mpsc::channel(UDP_PACKET_BUFFER_SIZE);
		match stream {
			SocketOrTunnelStream::Socket(s) => {
				debug!(
					"Creating UDP socket connection for (src: {}, outbound_ind: {})",
					sess.src, outbound_ind
				);
				self.spawn_socket(
					sess.src,
					outbound_ind,
					s,
					inbound_sender,
					outbound_sender.clone(),
					outbound_receiver,
				)
				.await;
			}
			SocketOrTunnelStream::Tunnel(stream) => {
				debug!(
					"Creating UDP tunnel connection for (src: {}, dst: {})",
					sess.src, sess.dst
				);
				self.spawn_tunnel(
					sess,
					stream,
					inbound_sender,
					outbound_sender.clone(),
					outbound_receiver,
				)
				.await;
			}
		};
		Ok(outbound_sender)
	}

	async fn spawn_socket(
		&self,
		src: SocketAddr,
		outbound_ind: usize,
		stream: socket::PacketStream,
		inbound_sender: DataSender,
		outbound_sender: DataSender,
		outbound_receiver: DataReceiver,
	) {
		let last_active_time = Arc::new(AsyncMutex::new(Instant::now()));
		let (read_half, write_half) = (stream.read_half, stream.write_half);

		// Read data from outbound and send it to inbound
		let read_task = {
			let map = self.sockets.clone();
			let last_active_time = last_active_time.clone();
			async move {
				let res = socket_to_sender(src, read_half, inbound_sender, last_active_time).await;
				// Remove sender from map when finished
				map.lock().await.remove(src, outbound_ind);
				res
			}
		};
		// Receive data from inbound, and write it to outbound
		let write_task = {
			let map = self.sockets.clone();
			let last_active_time = last_active_time.clone();
			async move {
				let res = receiver_to_socket(write_half, outbound_receiver, last_active_time).await;
				map.lock().await.remove(src, outbound_ind);
				res
			}
		};

		let handle = tokio::spawn(async move {
			futures::pin_mut!(read_task);
			futures::pin_mut!(write_task);
			select_timeout(TASK_TIMEOUT, read_task, write_task).await;
		});

		self.sockets.lock().await.insert(
			src,
			outbound_ind,
			SocketConnection::new(outbound_sender, last_active_time, handle),
		);
	}

	async fn spawn_tunnel<'a>(
		&'a self,
		sess: &'a Session,
		stream: tunnel::PacketStream,
		inbound_sender: DataSender,
		outbound_sender: DataSender,
		outbound_receiver: DataReceiver,
	) {
		let last_active_time = Arc::new(AsyncMutex::new(Instant::now()));
		let (read_half, write_half) = (stream.read_half, stream.write_half);

		// Read from outbound, and send to inbound
		let read_task = {
			let map = self.tunnels.clone();
			let last_active_time = last_active_time.clone();
			let sess = sess.clone();
			async move {
				let res =
					tunnel_to_sender(sess.clone(), read_half, inbound_sender, last_active_time)
						.await;
				map.lock().await.remove(&sess);
				res
			}
		};
		// Receive from inbound, and write to outbound

		let write_task = {
			let map = self.tunnels.clone();
			let sess = sess.clone();
			let last_active_time = last_active_time.clone();
			async move {
				let res = receiver_to_tunnel(write_half, outbound_receiver, last_active_time).await;
				map.lock().await.remove(&sess);
				res
			}
		};

		let handle = tokio::spawn(async move {
			futures::pin_mut!(read_task);
			futures::pin_mut!(write_task);
			select_timeout(TASK_TIMEOUT, read_task, write_task).await;
		});

		self.tunnels.lock().await.insert(
			sess.clone(),
			TunnelConnection::new(outbound_sender.clone(), last_active_time, handle),
		);
	}
}

struct SocketConnection {
	sender: DataSender,
	last_active_time: ArcMutex<Instant>,
	handle: JoinHandle<()>,
}

impl SocketConnection {
	fn new(
		sender: DataSender,
		last_active_time: ArcMutex<Instant>,
		handle: JoinHandle<()>,
	) -> Self {
		Self {
			sender,
			last_active_time,
			handle,
		}
	}

	async fn check_timeout(&self, now: Instant, max_elapsed: Duration) -> bool {
		let elapsed = now - *self.last_active_time.lock().await;
		elapsed > max_elapsed
	}

	fn close(&mut self) {
		self.handle.abort();
	}
}

struct TunnelConnection {
	sender: DataSender,
	last_active_time: ArcMutex<Instant>,
	handle: JoinHandle<()>,
}

impl TunnelConnection {
	fn new(
		sender: DataSender,
		last_active_time: ArcMutex<Instant>,
		handle: JoinHandle<()>,
	) -> Self {
		Self {
			sender,
			last_active_time,
			handle,
		}
	}

	async fn check_outdated(&self, now: Instant, max_elapsed: Duration) -> bool {
		let elapsed = now - *self.last_active_time.lock().await;
		elapsed > max_elapsed
	}

	fn close(&mut self) {
		self.handle.abort();
	}
}

#[derive(Default)]
struct SocketsMap {
	map: HashMap<(SocketAddr, usize), SocketConnection>,
}

impl SocketsMap {
	fn get(&self, addr: SocketAddr, outbound_ind: usize) -> Option<&SocketConnection> {
		self.map.get(&(addr, outbound_ind))
	}

	fn insert(&mut self, src: SocketAddr, outbound_ind: usize, conn: SocketConnection) {
		self.map.insert((src, outbound_ind), conn);
	}

	fn remove(&mut self, src: SocketAddr, outbound_ind: usize) {
		if let Some(mut conn) = self.map.remove(&(src, outbound_ind)) {
			trace!(
				"Removing UDP socket connection for (src {}, outbound_ind {}) from SocketsMap, remaining: {}",
				src,
				outbound_ind,
				self.map.len()
			);
			conn.close();
		}
	}

	fn remove_all(&mut self) {
		// Close and remove all connections
		for ((src, outbound_ind), conn) in &mut self.map {
			trace!(
				"Removing UDP socket connection for (src {}, outbound_ind {}) from SocketsMap",
				src,
				outbound_ind
			);
			conn.close();
		}
		self.map.clear();
	}
}

#[derive(Default)]
struct TunnelsMap {
	map: HashMap<Session, TunnelConnection>,
}

impl TunnelsMap {
	fn get(&self, sess: &Session) -> Option<&TunnelConnection> {
		self.map.get(sess)
	}

	fn insert(&mut self, sess: Session, conn: TunnelConnection) {
		self.map.insert(sess, conn);
	}

	fn remove(&mut self, sess: &Session) -> Option<TunnelConnection> {
		if let Some(mut conn) = self.map.remove(sess) {
			trace!(
				"Removing UDP tunnel connection for (src {}, dst {}) from TunnelsMap, remaining: {}",
				sess.src,
				sess.dst,
				self.map.len()
			);
			conn.close();
			Some(conn)
		} else {
			None
		}
	}

	fn remove_all(&mut self) {
		// Close and remove all connections
		for (sess, conn) in &mut self.map {
			trace!(
				"Removing UDP tunnel connection for (src {}, dst {}) from TunnelsMap",
				sess.src,
				sess.dst
			);
			conn.close();
		}
		self.map.clear();
	}
}

async fn socket_to_sender(
	src: SocketAddr,
	mut read_half: Box<dyn socket::RecvPacket>,
	mut inbound_sender: DataSender,
	last_active_time: ArcMutex<Instant>,
) -> Result<(), io::Error> {
	loop {
		let mut buf = BytesMut::new();
		buf.resize(UDP_BUFFER_SIZE, 0);

		// Read packet from outbound
		let (len, dst) = read_half.recv_src(&mut buf).await?;
		if len == 0 {
			break;
		}
		*last_active_time.lock().await = Instant::now();

		// Send packet to inbound
		// Error means
		buf.truncate(len);
		if let Err(e) = inbound_sender
			.send((Session { src, dst }, buf.freeze()))
			.await
		{
			error!("Cannot send outbound data to inbound: {}", e);
			return Err(io::Error::new(io::ErrorKind::Other, e));
		}
	}
	Ok(())
}

async fn receiver_to_socket(
	mut write_half: Box<dyn socket::SendPacket>,
	mut receiver: DataReceiver,
	last_active_time: ArcMutex<Instant>,
) -> Result<(), io::Error> {
	while let Some((sess, data)) = receiver.next().await {
		write_half.send_dst(&sess.dst, &data).await?;
		*last_active_time.lock().await = Instant::now();
	}
	Result::<(), io::Error>::Ok(())
}

async fn tunnel_to_sender(
	sess: Session,
	mut read_half: Box<dyn tunnel::RecvPacket>,
	mut inbound_sender: DataSender,
	last_active_time: ArcMutex<Instant>,
) -> Result<(), io::Error> {
	loop {
		let mut buf = BytesMut::new();
		buf.resize(UDP_BUFFER_SIZE, 0);

		// Read packet from outbound
		let len = read_half.recv(&mut buf).await?;
		if len == 0 {
			break;
		}
		*last_active_time.lock().await = Instant::now();

		// Send packet to inbound
		buf.truncate(len);
		if let Err(e) = inbound_sender.send((sess.clone(), buf.freeze())).await {
			return Err(io::Error::new(io::ErrorKind::Other, e));
		};
	}
	Ok(())
}

async fn receiver_to_tunnel(
	mut write_half: Box<dyn tunnel::SendPacket>,
	mut receiver: DataReceiver,
	last_active_time: ArcMutex<Instant>,
) -> Result<(), io::Error> {
	while let Some((_sess, data)) = receiver.next().await {
		write_half.send(&data).await?;
		*last_active_time.lock().await = Instant::now();
	}
	Result::<(), io::Error>::Ok(())
}
