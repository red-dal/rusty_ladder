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
	data::{Connection, CounterValue, SessionState},
	Id, Network, SessionBasicInfo, Snapshot, Tag,
};
use crate::{
	prelude::*,
	server::stat::data::{OutboundInfo, SessionCounter},
	utils::relay::Counter,
};
use futures::Future;
use parking_lot::Mutex;
use std::{
	borrow::Cow,
	collections::HashMap,
	collections::VecDeque,
	sync::Arc,
	time::{Duration, Instant, SystemTime},
};

const DEAD_CONNS_BUFFER_SIZE: usize = 8;
const UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const SEC_TO_MS: u64 = 1000;

// #[derive(Debug, thiserror::Error)]
// pub enum Error {
// 	#[error("connection {0:x} already exists, could be coding error.")]
// 	AlreadyExist(Id),
// 	#[error("connection {0:x} cannot be found, could be coding error.")]
// 	NotFound(Id),
// 	#[error("connection '{0}' state error: {1}")]
// 	WrongState(Id, Cow<'static, str>),
// }
//
// impl From<Error> for ServerError {
// 	#[inline]
// 	fn from(e: Error) -> Self {
// 		Self::Other(e.into())
// 	}
// }

#[allow(clippy::module_name_repetitions)]
type ArcInternal = Arc<Mutex<Internal>>;

#[derive(Clone)]
pub struct Monitor(ArcInternal);

impl Monitor {
	pub fn new() -> (Self, impl Future<Output = ()>) {
		let mon = Internal {
			conns: HashMap::default(),
			dead_conns: VecDeque::with_capacity(DEAD_CONNS_BUFFER_SIZE),
		};
		let mon = Arc::new(Mutex::new(mon));
		let task = update_speed(mon.clone());
		(Self(mon), task)
	}

	/// Register a new connection in the monitor and returns a [`Handle`].
	///
	/// # Panics
	///
	/// Panics if a connection with the same id is already registered.
	#[must_use]
	pub fn register_tcp_session(&self, args: RegisterArgs) -> SessionHandle {
		let conn_id = args.conn_id;
		self.0
			.lock()
			.new_handshake(args.into_handshake_args(Network::Tcp));
		SessionHandle {
			monitor: self.clone(),
			conn_id,
		}
	}

	/// Register a new connection in the monitor and returns a [`Handle`].
	///
	/// # Panics
	///
	/// Panics if a connection with the same id is already registered.
	#[cfg(feature = "use-udp")]
	#[must_use]
	pub fn register_udp_session(&self, args: RegisterArgs) -> SessionHandle {
		let sess_id = args.conn_id;
		self.0
			.lock()
			.new_handshake(args.into_handshake_args(Network::Udp));
		SessionHandle {
			monitor: self.clone(),
			conn_id: sess_id,
		}
	}

	pub fn query(&self, filter: &Filter, result: &mut Vec<Snapshot>) {
		self.0.lock().query(filter, result);
	}
}

pub struct RegisterArgs {
	pub conn_id: Id,
	pub inbound_ind: usize,
	pub inbound_tag: Tag,
	pub start_time: SystemTime,
	pub from: SocketAddr,
}

impl RegisterArgs {
	fn into_handshake_args(self, net: Network) -> SessionBasicInfo {
		SessionBasicInfo {
			conn_id: self.conn_id,
			inbound_ind: self.inbound_ind,
			inbound_tag: self.inbound_tag,
			start_time: self.start_time,
			from: self.from,
			net,
		}
	}
}

/// Record and manage the stat of every connection.
struct Internal {
	conns: HashMap<Id, Connection>,
	dead_conns: VecDeque<Snapshot>,
}

impl Internal {
	fn new_handshake(&mut self, args: SessionBasicInfo) {
		let conn_id = args.conn_id;
		// no connections should share the same id

		assert!(
			!self.conns.contains_key(&conn_id),
			"Connection[{:x}] already in the monitor",
			conn_id
		);

		self.conns.insert(
			conn_id,
			Connection {
				basic: args,
				state: SessionState::Handshaking,
			},
		);
	}

	fn set_connecting(
		&mut self,
		conn_id: Id,
		outbound_ind: usize,
		outbound_tag: Tag,
		to: SocksAddr,
	) {
		trace!("set connecting for conn {:x}", conn_id);
		if let Some(c) = self.conns.get_mut(&conn_id) {
			if let SessionState::Handshaking = c.state {
				c.state = SessionState::Connecting(OutboundInfo {
					to,
					outbound_ind,
					outbound_tag,
				});
			} else {
				panic!("invalid state transition {} -> connecting", c.state.name());
			}
		} else {
			panic!("Connection[{:x}] is not registered", conn_id);
		}
	}

	fn set_proxying(&mut self, conn_id: Id, recv: Counter, send: Counter) {
		trace!("set proxying for conn {:x}", conn_id);
		if let Some(c) = self.conns.get_mut(&conn_id) {
			c.state = if let SessionState::Connecting(out) = &c.state {
				SessionState::Proxying {
					out: out.clone(),
					counter: SessionCounter { recv, send },
					speed: CounterValue::new(),
				}
			} else {
				panic!("invalid state transition {} -> proxying", c.state.name());
			};
		} else {
			panic!("Connection[{:x}] is not registered", conn_id);
		}
	}

	fn set_dead(&mut self, conn_id: Id, end_time: SystemTime) {
		log::trace!("set dead for conn {conn_id:x}");

		if let Some(c) = self.conns.remove(&conn_id) {
			if self.dead_conns.len() >= DEAD_CONNS_BUFFER_SIZE {
				self.dead_conns.pop_front();
			}
			let dead = c.into_dead(end_time);
			self.dead_conns.push_back(dead);
		} else {
			log::error!("Connection[{conn_id:x}] is not registered or already dead");
		}
	}

	fn query(&self, filter: &Filter, result: &mut Vec<Snapshot>) {
		trace!("Querying with filter {:?}", filter);
		let capacity = filter.estimate_size().unwrap_or(16);
		result.clear();
		result.reserve(capacity);
		if filter.needs_alive() {
			let conns = &self.conns;
			for (_, c) in conns.iter() {
				if filter.check(&c.basic.inbound_tag, c.outbound_tag()) {
					result.push(Snapshot::new(c));
				}
			}
		}
		if filter.needs_dead() {
			for dc in &self.dead_conns {
				if filter.check(&dc.basic.inbound_tag, dc.outbound_tag()) {
					result.push(dc.clone());
				}
			}
		}
	}
}

#[derive(Clone)]
pub struct SessionHandle {
	monitor: Monitor,
	conn_id: Id,
}

impl SessionHandle {
	pub fn set_connecting(&self, outbound_ind: usize, outbound_tag: Tag, to: SocksAddr) {
		self.monitor
			.0
			.lock()
			.set_connecting(self.conn_id, outbound_ind, outbound_tag, to);
	}

	pub fn set_proxying(&self, recv: Counter, send: Counter) {
		self.monitor.0.lock().set_proxying(self.conn_id, recv, send);
	}

	pub fn set_dead(&self, end_time: SystemTime) {
		self.monitor.0.lock().set_dead(self.conn_id, end_time);
	}

	#[inline]
	#[must_use]
	pub fn monitor(&self) -> &Monitor {
		&self.monitor
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StateFilter {
	Alive,
	Dead,
	All,
}

impl FromStr for StateFilter {
	type Err = Cow<'static, str>;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"alive" => Ok(StateFilter::Alive),
			"dead" => Ok(StateFilter::Dead),
			"all" => Ok(StateFilter::All),
			_ => Err(format!("'{}' is not a valid StateFilter", s).into()),
		}
	}
}

#[derive(Debug, Clone)]
pub struct Filter {
	pub conn_ids: Option<Vec<Id>>,
	pub inbound_tags: Option<Vec<Tag>>,
	pub outbound_tags: Option<Vec<Tag>>,
	pub state: StateFilter,
}

impl Filter {
	#[inline]
	#[must_use]
	pub fn new_all() -> Self {
		Self {
			conn_ids: None,
			inbound_tags: None,
			outbound_tags: None,
			state: StateFilter::All,
		}
	}

	#[inline]
	#[must_use]
	pub fn with_ids(ids: Vec<Id>) -> Self {
		Self {
			conn_ids: Some(ids),
			inbound_tags: None,
			outbound_tags: None,
			state: StateFilter::All,
		}
	}

	#[inline]
	#[must_use]
	pub fn new_all_alive() -> Self {
		Self {
			conn_ids: None,
			inbound_tags: None,
			outbound_tags: None,
			state: StateFilter::Alive,
		}
	}

	#[inline]
	#[must_use]
	pub fn new_all_dead() -> Self {
		Self {
			conn_ids: None,
			inbound_tags: None,
			outbound_tags: None,
			state: StateFilter::Dead,
		}
	}

	/// Returns the estimated size of the filter result.
	fn estimate_size(&self) -> Option<usize> {
		self.conn_ids.as_ref().map(Vec::len)
	}

	#[inline]
	fn needs_alive(&self) -> bool {
		matches!(self.state, StateFilter::Alive | StateFilter::All)
	}

	#[inline]
	fn needs_dead(&self) -> bool {
		matches!(self.state, StateFilter::Dead | StateFilter::All)
	}

	fn check(&self, inbound_tag: &Tag, outbound_tag: Option<&Tag>) -> bool {
		if let Some(tags) = &self.inbound_tags {
			if !tags.contains(inbound_tag) {
				return false;
			}
		}

		if let Some(tags) = &self.outbound_tags {
			if let Some(outbound_tag) = outbound_tag {
				if !tags.contains(outbound_tag) {
					return false;
				}
			}
		}

		true
	}
}

async fn update_speed(mon: ArcInternal) {
	let mut last = Instant::now();
	let mut last_vals = HashMap::<Id, CounterValue>::new();
	loop {
		tokio::time::sleep(UPDATE_INTERVAL).await;
		let now = Instant::now();
		let elap_ms = u64::try_from(now.duration_since(last).as_millis())
			.expect("interval between update is too long!");
		last = now;
		trace!("Updating speed, elapsed ms: {}", elap_ms);

		// Update speeds.
		let mut mon = mon.lock();
		// Remove all connections that no longer exist.
		last_vals.retain(|id, _val| mon.conns.contains_key(id));

		// Calculate speed for each connection.
		for (id, conn) in &mut mon.conns {
			if let SessionState::Proxying {
				out: _,
				ref counter,
				speed,
			} = &mut conn.state
			{
				let curr_val = counter.get();
				let last_val = last_vals.entry(*id).or_insert_with(CounterValue::new);
				// Difference between each update shouldn't be large enough to overflow.
				let diff = curr_val - *last_val;
				speed.recv = diff.recv * SEC_TO_MS / elap_ms;
				speed.send = diff.send * SEC_TO_MS / elap_ms;

				*last_val = curr_val;
			};
		}
	}
}
