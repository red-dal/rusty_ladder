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
	server::stat::SessionHandle,
	utils::relay::Counter,
};
use bytes::BytesMut;
use futures::{channel::mpsc, Future, SinkExt, StreamExt};
use std::{
	collections::HashMap,
	io,
	sync::atomic::{AtomicBool, Ordering},
	time::{Duration, Instant, SystemTime},
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
					let systime_now = SystemTime::now();

					// Find timeout sessions and remove
					{
						let mut timeout_sockets = Vec::new();
						for (key, conn) in &sockets.map {
							if conn.check_inactive(now, UDP_TIMEOUT_DURATION) {
								debug!(
									"UDP socket for (src {}, outbound_ind {}) is outdated",
									key.0, key.1
								);
								timeout_sockets.push(*key);
							}
						}
						for (src, outbound_ind) in timeout_sockets {
							sockets.remove(src, outbound_ind, systime_now);
						}
					}
					{
						let mut timeout_tunnels = Vec::new();
						for (key, conn) in &tunnels.map {
							if conn.check_inactive(now, UDP_TIMEOUT_DURATION) {
								debug!(
									"UDP tunnel for src {}, dst {} is outdated",
									key.src, key.dst
								);
								timeout_tunnels.push(key.clone());
							}
						}
						for sess in timeout_tunnels {
							tunnels.remove(&sess, systime_now);
						}
					}
				}
				// Gracefully shutdown
				debug!("Shutting down ConnectionMap guard task. Clean up all connections");
				let now = SystemTime::now();
				sockets.lock().await.remove_all(now);
				tunnels.lock().await.remove_all(now);
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

	pub async fn register_session(
		&self,
		inbound_sender: DataSender,
		sess: &Session,
		sess_handle: Option<&SessionHandle>,
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

		let read_counter = Counter::new(0);
		let write_counter = Counter::new(0);
		if let Some(h) = sess_handle {
			h.set_proxying(read_counter.clone(), write_counter.clone());
		}

		let args = SpawnTaskArgs {
			sess,
			sess_handle,
			outbound_ind,
			inbound_sender,
			outbound_sender: outbound_sender.clone(),
			outbound_receiver,
			read_counter,
			write_counter,
		};

		match stream {
			SocketOrTunnelStream::Socket(stream) => {
				debug!(
					"Creating UDP socket connection for (src: {}, outbound_ind: {})",
					sess.src, outbound_ind
				);
				self.relay_socket_packets(stream, args).await;
			}
			SocketOrTunnelStream::Tunnel(stream) => {
				debug!(
					"Creating UDP tunnel connection for (src: {}, dst: {})",
					sess.src, sess.dst
				);
				self.relay_tunnel_packets(stream, args).await;
			}
		};
		Ok(outbound_sender)
	}

	async fn relay_socket_packets(&self, stream: socket::PacketStream, args: SpawnTaskArgs<'_>) {
		let last_active_time = ArcInstant::new(Instant::now());
		let (read_half, write_half) = (stream.read_half, stream.write_half);

		let src = args.sess.src;
		let outbound_ind = args.outbound_ind;

		let read_counter = args.read_counter;
		let write_counter = args.write_counter;

		// Read data from outbound and send it to inbound
		let read_task = {
			let map = self.sockets.clone();
			let last_active_time = last_active_time.clone();
			let inbound_sender = args.inbound_sender;
			async move {
				let res = copy_from_socket_to_sender(
					src,
					read_half,
					inbound_sender,
					last_active_time,
					read_counter.clone(),
				)
				.await;
				// Remove sender from map when finished
				map.lock()
					.await
					.remove(src, outbound_ind, SystemTime::now());
				res
			}
		};
		// Receive data from inbound, and write it to outbound
		let write_task = {
			let map = self.sockets.clone();
			let last_active_time = last_active_time.clone();
			let outbound_receiver = args.outbound_receiver;

			async move {
				let res = copy_from_receiver_to_socket(
					write_half,
					outbound_receiver,
					last_active_time,
					write_counter.clone(),
				)
				.await;
				map.lock()
					.await
					.remove(src, outbound_ind, SystemTime::now());
				res
			}
		};

		let sess_handle = args.sess_handle.cloned();
		let handle = {
			let sess_handle = sess_handle.clone();
			tokio::spawn(async move {
				futures::pin_mut!(read_task);
				futures::pin_mut!(write_task);
				select_timeout(TASK_TIMEOUT, read_task, write_task).await;
				if let Some(h) = &sess_handle {
					h.set_dead(SystemTime::now());
				}
			})
		};

		self.sockets.lock().await.insert(
			src,
			outbound_ind,
			SocketConnection::new(args.outbound_sender, last_active_time, handle, sess_handle),
		);
	}

	async fn relay_tunnel_packets(&self, stream: tunnel::PacketStream, args: SpawnTaskArgs<'_>) {
		let last_active_time = ArcInstant::new(Instant::now());
		let (read_half, write_half) = (stream.read_half, stream.write_half);

		// Read from outbound, and send to inbound
		let read_task = {
			let map = self.tunnels.clone();
			let last_active_time = last_active_time.clone();
			let sess = args.sess.clone();
			let inbound_sender = args.inbound_sender;
			let read_counter = args.read_counter;
			async move {
				let res = tunnel_to_sender(
					&sess,
					read_half,
					inbound_sender,
					last_active_time,
					read_counter,
				)
				.await;
				map.lock().await.remove(&sess, SystemTime::now());
				res
			}
		};
		// Receive from inbound, and write to outbound

		let write_task = {
			let map = self.tunnels.clone();
			let sess = args.sess.clone();
			let last_active_time = last_active_time.clone();
			let outbound_receiver = args.outbound_receiver;
			let write_counter = args.write_counter;
			async move {
				let res = receiver_to_tunnel(
					write_half,
					outbound_receiver,
					last_active_time,
					&write_counter,
				)
				.await;
				map.lock().await.remove(&sess, SystemTime::now());
				res
			}
		};

		let sess_handle = args.sess_handle.cloned();
		let handle = {
			let sess_handle = sess_handle.clone();
			tokio::spawn(async move {
				futures::pin_mut!(read_task);
				futures::pin_mut!(write_task);
				select_timeout(TASK_TIMEOUT, read_task, write_task).await;
				if let Some(h) = sess_handle {
					h.set_dead(SystemTime::now());
				}
			})
		};

		self.tunnels.lock().await.insert(
			args.sess.clone(),
			TunnelConnection::new(
				args.outbound_sender.clone(),
				last_active_time,
				handle,
				sess_handle,
			),
		);
	}
}

struct SpawnTaskArgs<'a> {
	sess: &'a Session,
	sess_handle: Option<&'a SessionHandle>,
	outbound_ind: usize,
	inbound_sender: DataSender,
	outbound_sender: DataSender,
	outbound_receiver: DataReceiver,
	read_counter: Counter,
	write_counter: Counter,
}

struct SocketConnection {
	sender: DataSender,
	last_active_time: ArcInstant,
	handle: JoinHandle<()>,
	sess_handle: Option<SessionHandle>,
}

impl SocketConnection {
	fn new(
		sender: DataSender,
		last_active_time: ArcInstant,
		handle: JoinHandle<()>,
		sess_handle: Option<SessionHandle>,
	) -> Self {
		Self {
			sender,
			last_active_time,
			handle,
			sess_handle,
		}
	}

	fn check_inactive(&self, now: Instant, max_elapsed: Duration) -> bool {
		let elapsed = now - self.last_active_time.get();
		elapsed > max_elapsed
	}

	fn close(&mut self, now: SystemTime) {
		if let Some(h) = &self.sess_handle {
			h.set_dead(now);
		}
		self.handle.abort();
	}
}

struct TunnelConnection {
	sender: DataSender,
	last_active_time: ArcInstant,
	handle: JoinHandle<()>,
	sess_handle: Option<SessionHandle>,
}

impl TunnelConnection {
	fn new(
		sender: DataSender,
		last_active_time: ArcInstant,
		handle: JoinHandle<()>,
		sess_handle: Option<SessionHandle>,
	) -> Self {
		Self {
			sender,
			last_active_time,
			handle,
			sess_handle,
		}
	}

	fn check_inactive(&self, now: Instant, max_elapsed: Duration) -> bool {
		let elapsed = now - self.last_active_time.get();
		elapsed > max_elapsed
	}

	fn close(&mut self, now: SystemTime) {
		if let Some(h) = &self.sess_handle {
			h.set_dead(now);
		}
		self.handle.abort();
	}
}

#[derive(Default)]
struct SocketsMap {
	/// A map of (dest_addr, outbound_ind)->SocketConnection.
	map: HashMap<(SocketAddr, usize), SocketConnection>,
}

impl SocketsMap {
	fn get(&self, addr: SocketAddr, outbound_ind: usize) -> Option<&SocketConnection> {
		self.map.get(&(addr, outbound_ind))
	}

	fn insert(&mut self, src: SocketAddr, outbound_ind: usize, conn: SocketConnection) {
		self.map.insert((src, outbound_ind), conn);
	}

	fn remove(&mut self, src: SocketAddr, outbound_ind: usize, now: SystemTime) {
		if let Some(mut conn) = self.map.remove(&(src, outbound_ind)) {
			trace!(
				"Removing UDP socket connection for (src {}, outbound_ind {}) from SocketsMap, remaining: {}",
				src,
				outbound_ind,
				self.map.len()
			);
			conn.close(now);
		}
	}

	fn remove_all(&mut self, now: SystemTime) {
		// Close and remove all connections
		for ((src, outbound_ind), conn) in &mut self.map {
			trace!(
				"Removing UDP socket connection for (src {}, outbound_ind {}) from SocketsMap",
				src,
				outbound_ind
			);
			conn.close(now);
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

	fn remove(&mut self, sess: &Session, now: SystemTime) -> Option<TunnelConnection> {
		if let Some(mut conn) = self.map.remove(sess) {
			trace!(
				"Removing UDP tunnel connection for (src {}, dst {}) from TunnelsMap, remaining: {}",
				sess.src,
				sess.dst,
				self.map.len()
			);
			conn.close(now);
			Some(conn)
		} else {
			None
		}
	}

	fn remove_all(&mut self, now: SystemTime) {
		// Close and remove all connections
		for (sess, conn) in &mut self.map {
			trace!(
				"Removing UDP tunnel connection for (src {}, dst {}) from TunnelsMap",
				sess.src,
				sess.dst
			);
			conn.close(now);
		}
		self.map.clear();
	}
}

async fn copy_from_socket_to_sender(
	src: SocketAddr,
	mut read_half: Box<dyn socket::RecvPacket>,
	mut inbound_sender: DataSender,
	last_active_time: ArcInstant,
	counter: Counter,
) -> Result<(), io::Error> {
	loop {
		let mut buf = BytesMut::new();
		buf.resize(UDP_BUFFER_SIZE, 0);

		// Read packet from outbound
		let (len, dst) = read_half.recv_src(&mut buf).await?;
		if len == 0 {
			break;
		}
		last_active_time.set(Instant::now());

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

		counter.add(usize_to_u64(len));
	}
	Ok(())
}

async fn copy_from_receiver_to_socket(
	mut write_half: Box<dyn socket::SendPacket>,
	mut receiver: DataReceiver,
	last_active_time: ArcInstant,
	counter: Counter,
) -> Result<(), io::Error> {
	while let Some((sess, data)) = receiver.next().await {
		write_half.send_dst(&sess.dst, &data).await?;
		counter.add(usize_to_u64(data.len()));
		last_active_time.set(Instant::now());
	}
	Result::<(), io::Error>::Ok(())
}

async fn tunnel_to_sender(
	sess: &Session,
	mut read_half: Box<dyn tunnel::RecvPacket>,
	mut inbound_sender: DataSender,
	last_active_time: ArcInstant,
	counter: Counter,
) -> Result<(), io::Error> {
	loop {
		let mut buf = BytesMut::new();
		buf.resize(UDP_BUFFER_SIZE, 0);

		// Read packet from outbound
		let len = read_half.recv(&mut buf).await?;
		if len == 0 {
			break;
		}
		last_active_time.set(Instant::now());

		// Send packet to inbound
		buf.truncate(len);
		if let Err(e) = inbound_sender.send((sess.clone(), buf.freeze())).await {
			return Err(io::Error::new(io::ErrorKind::Other, e));
		};
		counter.add(usize_to_u64(len));
	}
	Ok(())
}

async fn receiver_to_tunnel(
	mut write_half: Box<dyn tunnel::SendPacket>,
	mut receiver: DataReceiver,
	last_active_time: ArcInstant,
	counter: &Counter,
) -> Result<(), io::Error> {
	while let Some((_sess, data)) = receiver.next().await {
		write_half.send(&data).await?;
		last_active_time.set(Instant::now());
		counter.add(usize_to_u64(data.len()));
	}
	Result::<(), io::Error>::Ok(())
}

#[inline]
fn usize_to_u64(value: usize) -> u64 {
	u64::try_from(value).expect("Cannot convert usize to u64")
}

#[derive(Clone)]
struct ArcInstant(Arc<parking_lot::Mutex<Instant>>);

impl ArcInstant {
	pub fn new(instant: Instant) -> Self {
		Self(Arc::new(parking_lot::Mutex::new(instant)))
	}

	pub fn get(&self) -> Instant {
		*self.0.lock()
	}

	pub fn set(&self, now: Instant) {
		*self.0.lock() = now;
	}
}
