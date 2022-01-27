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

use super::BuildError;
use std::{borrow::Cow, time::Duration};

const fn default_dial_tcp_timeout_ms() -> u64 {
	10_000
}

const fn default_outbound_handshake_timeout_ms() -> u64 {
	20_000
}

const fn default_relay_timeout_secs() -> usize {
	300
}

#[cfg(feature = "use-udp")]
const fn default_udp_session_timeout_ms() -> u64 {
	20_000
}

pub struct Global {
	/// TCP connection will be dropped if it cannot be established within this amount of time.
	pub dial_tcp_timeout: Duration,
	pub outbound_handshake_timeout: Duration,
	pub relay_timeout_secs: usize,
	#[cfg(feature = "use-udp")]
	pub udp_session_timeout: Duration,
}

impl Default for Global {
	fn default() -> Self {
		Builder::default().build().unwrap()
	}
}

#[derive(Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct Builder {
	/// TCP connection will be dropped if it cannot be established within
	/// this amount of time.
	///
	/// Default: 10000
	#[cfg_attr(feature = "use_serde", serde(default = "default_dial_tcp_timeout_ms"))]
	pub dial_tcp_timeout_ms: u64,
	/// Outbound handshake will be dropped if it cannot be completed within
	/// this amount of time.
	///
	/// Default: 20000
	#[cfg_attr(
		feature = "use_serde",
		serde(default = "default_outbound_handshake_timeout_ms")
	)]
	pub outbound_handshake_timeout_ms: u64,
	/// Session will be dropped if there are no bytes transferred within
	/// this amount of time.
	///
	/// Defaults: 300
	#[cfg_attr(feature = "use_serde", serde(default = "default_relay_timeout_secs"))]
	pub relay_timeout_secs: usize,
	/// Udp socket/tunnel session will be dropped if there is no read or write for more than
	/// this amount of time.
	///
	/// Defaults: 20000
	#[cfg(feature = "use-udp")]
	#[cfg_attr(
		feature = "use_serde",
		serde(default = "default_udp_session_timeout_ms")
	)]
	pub udp_session_timeout_ms: u64,
}

impl Builder {
	pub fn build(&self) -> Result<Global, BuildError> {
		check_zero(self.dial_tcp_timeout_ms, "dial_tcp_timeout_ms")?;
		check_zero(
			self.outbound_handshake_timeout_ms,
			"outbound_handshake_timeout_ms",
		)?;
		check_zero_usize(self.relay_timeout_secs, "relay_timeout_secs")?;

		#[cfg(feature = "use-udp")]
		check_zero(self.udp_session_timeout_ms, "udp_session_timeout_ms")?;
		Ok(Global {
			dial_tcp_timeout: Duration::from_millis(self.dial_tcp_timeout_ms),
			outbound_handshake_timeout: Duration::from_millis(self.outbound_handshake_timeout_ms),
			relay_timeout_secs: self.relay_timeout_secs,
			#[cfg(feature = "use-udp")]
			udp_session_timeout: Duration::from_millis(self.udp_session_timeout_ms),
		})
	}
}

impl Default for Builder {
	fn default() -> Self {
		Self {
			dial_tcp_timeout_ms: default_dial_tcp_timeout_ms(),
			outbound_handshake_timeout_ms: default_outbound_handshake_timeout_ms(),
			relay_timeout_secs: default_relay_timeout_secs(),
			#[cfg(feature = "use-udp")]
			udp_session_timeout_ms: default_udp_session_timeout_ms(),
		}
	}
}

/// Returns Err([`BuildError::ValueIsZero`]) if `val` is zero.
#[inline]
fn check_zero_usize(val: usize, val_name: &'static str) -> Result<usize, BuildError> {
	check_zero(val as u64, val_name).map(|_| val)
}

/// Returns Err([`BuildError::ValueIsZero`]) if `val` is zero.
#[inline]
fn check_zero(val: u64, val_name: &'static str) -> Result<u64, BuildError> {
	if val > 0 {
		Ok(val)
	} else {
		Err(BuildError::ValueIsZero(Cow::Borrowed(val_name)))
	}
}
