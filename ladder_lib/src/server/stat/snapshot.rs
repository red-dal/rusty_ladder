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
	data::{self, CounterValue},
	SessionBasicInfo, Tag,
};
use crate::protocol::SocksAddr;
use std::time::SystemTime;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "use-webapi", derive(serde::Serialize))]
pub struct StateConnecting {
	pub to: SocksAddr,
	pub outbound_ind: usize,
	pub outbound_tag: Tag,
}

impl From<&data::OutboundInfo> for StateConnecting {
	fn from(v: &data::OutboundInfo) -> Self {
		Self {
			to: v.to.clone(),
			outbound_ind: v.outbound_ind,
			outbound_tag: v.outbound_tag.clone(),
		}
	}
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "use-webapi", derive(serde::Serialize), serde(tag = "type"))]
pub enum State {
	/// Handshaking with client.
	Handshaking,
	/// Connecting to target server.
	Connecting(StateConnecting),
	/// Proxying payload.
	Proxying {
		#[cfg_attr(feature = "use-webapi", serde(flatten))]
		out: StateConnecting,
		recv: u64,
		send: u64,
		recv_speed: u64,
		send_speed: u64,
	},
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "use-webapi", derive(serde::Serialize))]
pub struct Snapshot {
	#[cfg_attr(feature = "use-webapi", serde(flatten))]
	pub basic: SessionBasicInfo,
	pub state: State,
	pub end_time: Option<SystemTime>,
}

impl Snapshot {
	#[must_use]
    #[inline]
	pub fn id(&self) -> u64 {
		self.basic.conn_id
	}

	#[must_use]
	pub fn outbound_tag(&self) -> Option<&Tag> {
		match &self.state {
			State::Handshaking => None,
			State::Connecting(i) => Some(&i.outbound_tag),
			State::Proxying {
				out,
				recv: _,
				send: _,
				recv_speed: _,
				send_speed: _,
			} => Some(&out.outbound_tag),
		}
	}

	#[must_use]
	pub fn outbound_ind(&self) -> Option<usize> {
		match &self.state {
			State::Handshaking => None,
			State::Connecting(i) => Some(i.outbound_ind),
			State::Proxying {
				out,
				recv: _,
				send: _,
				recv_speed: _,
				send_speed: _,
			} => Some(out.outbound_ind),
		}
	}

	#[must_use]
	pub fn to(&self) -> Option<&SocksAddr> {
		match &self.state {
			State::Handshaking => None,
			State::Connecting(i) => Some(&i.to),
			State::Proxying {
				out,
				recv: _,
				send: _,
				recv_speed: _,
				send_speed: _,
			} => Some(&out.to),
		}
	}

	#[must_use]
	pub fn recv(&self) -> u64 {
		match &self.state {
			State::Handshaking | State::Connecting(_) => 0,
			State::Proxying {
				out: _,
				recv,
				send: _,
				recv_speed: _,
				send_speed: _,
			} => *recv,
		}
	}

	#[must_use]
	pub fn send(&self) -> u64 {
		match &self.state {
			State::Handshaking | State::Connecting(_) => 0,
			State::Proxying {
				out: _,
				recv: _,
				send,
				recv_speed: _,
				send_speed: _,
			} => *send,
		}
	}

	#[inline]
	#[must_use]
	pub fn speed(&self) -> CounterValue {
		if let State::Proxying {
			out: _,
			recv: _,
			send: _,
			recv_speed,
			send_speed,
		} = &self.state
		{
			if !self.is_dead() {
				return CounterValue {
					recv: *recv_speed,
					send: *send_speed,
				};
			}
		}
		CounterValue::new()
	}

	#[must_use]
	pub fn is_dead(&self) -> bool {
		self.end_time.is_some()
	}

	pub(super) fn new(conn: &data::Connection) -> Self {
		let state = match &conn.state {
			data::SessionState::Handshaking => State::Handshaking,
			data::SessionState::Connecting(s) => State::Connecting(s.into()),
			data::SessionState::Proxying {
				out,
				counter,
				speed,
			} => {
				let val = counter.get();
				State::Proxying {
					out: out.into(),
					recv: val.recv,
					send: val.send,
					recv_speed: speed.recv,
					send_speed: speed.send,
				}
			}
		};
		Snapshot {
			basic: conn.basic.clone(),
			state,
			end_time: None,
		}
	}
}
