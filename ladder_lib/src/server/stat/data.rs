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

use super::{Id, Snapshot, Tag};
use crate::{protocol::SocksAddr, utils::relay::Counter};
use std::{
	net::SocketAddr,
	ops::{Add, AddAssign, Sub, SubAssign},
	time::SystemTime,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "use-webapi", derive(serde::Serialize))]
pub struct HandshakeArgs {
	#[cfg_attr(
		feature = "use-webapi",
		serde(serialize_with = "super::webapi::serde_conn_id::serialize")
	)]
	pub conn_id: Id,
	pub inbound_ind: usize,
	pub inbound_tag: Tag,
	pub start_time: SystemTime,
	pub from: SocketAddr,
}

#[derive(Debug, Clone)]
pub(super) struct OutboundInfo {
	pub to: SocksAddr,
	pub outbound_ind: usize,
	pub outbound_tag: Tag,
}

pub struct SessionCounter {
	pub recv: Counter,
	pub send: Counter,
}

impl SessionCounter {
	pub fn get(&self) -> CounterValue {
		CounterValue {
			recv: self.recv.get(),
			send: self.send.get(),
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub struct CounterValue {
	pub recv: u64,
	pub send: u64,
}

impl CounterValue {
	#[inline]
	#[must_use]
	pub const fn new() -> CounterValue {
		CounterValue { recv: 0, send: 0 }
	}
}

impl Add<&CounterValue> for &CounterValue {
	type Output = CounterValue;

	#[inline]
	fn add(self, rhs: &CounterValue) -> Self::Output {
		CounterValue {
			recv: self.recv + rhs.recv,
			send: self.send + rhs.send,
		}
	}
}

impl Add<CounterValue> for CounterValue {
	type Output = CounterValue;

	#[inline]
	fn add(self, rhs: CounterValue) -> Self::Output {
		Add::<&CounterValue>::add(&self, &rhs)
	}
}

impl AddAssign<&CounterValue> for CounterValue {
	#[inline]
	fn add_assign(&mut self, rhs: &CounterValue) {
		self.recv += rhs.recv;
		self.send += rhs.send;
	}
}

impl AddAssign<CounterValue> for CounterValue {
	#[inline]
	fn add_assign(&mut self, rhs: CounterValue) {
		AddAssign::<&CounterValue>::add_assign(self, &rhs);
	}
}

impl Sub<&CounterValue> for &CounterValue {
	type Output = CounterValue;

	#[inline]
	fn sub(self, rhs: &CounterValue) -> Self::Output {
		CounterValue {
			recv: self.recv - rhs.recv,
			send: self.send - rhs.send,
		}
	}
}

impl Sub<CounterValue> for CounterValue {
	type Output = CounterValue;

	#[inline]
	fn sub(self, rhs: CounterValue) -> Self::Output {
		Sub::<&CounterValue>::sub(&self, &rhs)
	}
}

impl SubAssign<&CounterValue> for CounterValue {
	#[inline]
	fn sub_assign(&mut self, rhs: &CounterValue) {
		self.recv -= rhs.recv;
		self.send -= rhs.send;
	}
}

impl SubAssign<CounterValue> for CounterValue {
	#[inline]
	fn sub_assign(&mut self, rhs: CounterValue) {
		SubAssign::<&CounterValue>::sub_assign(self, &rhs);
	}
}

pub(super) enum SessionState {
	Handshaking,
	Connecting(OutboundInfo),
	Proxying {
		out: OutboundInfo,
		counter: SessionCounter,
		speed: CounterValue,
	},
}

impl SessionState {
	pub fn name(&self) -> &'static str {
		match self {
			SessionState::Handshaking => "handshaking",
			SessionState::Connecting(_) => "connecting",
			SessionState::Proxying {
				out: _,
				counter: _,
				speed: _,
			} => "proxying",
		}
	}
}

pub(super) struct Connection {
	pub basic: HandshakeArgs,
	pub state: SessionState,
}

impl Connection {
	pub async fn into_dead(mut self, end_time: SystemTime) -> Snapshot {
		if let SessionState::Proxying {
			out: _,
			counter: _,
			speed,
		} = &mut self.state
		{
			*speed = CounterValue::new();
		}
		let mut dead = Snapshot::new(&self);
		dead.end_time = Some(end_time);
		dead
	}

	pub fn outbound_tag(&self) -> Option<&Tag> {
		match &self.state {
			SessionState::Handshaking => None,
			SessionState::Connecting(i) => Some(&i.outbound_tag),
			SessionState::Proxying {
				out,
				counter: _,
				speed: _,
			} => Some(&out.outbound_tag),
		}
	}
}
