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

/*!
An implementation of the vmess protocol.
See more at <https://www.v2fly.org/>

Currently only supports:
- AES-128-GCM, CHACHA20-POLY1305, NONE encryption (no AUTO and AES-128-CFB)
- single connection (no dynamic ports)
- only one UUID (no alterId)

As a result, DO NOT use this implementation of the vmess protocol directly through unsecure network.
*/

#[macro_use]
mod macro_helper;

#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
pub mod inbound;
#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
pub mod outbound;

mod aead_header;
mod request;
mod response;
mod utils;

mod crypto;

pub use utils::{Iv, Key, SecurityType};

use request::{Command, Request};
use response::Response;

pub const PROTOCOL_NAME: &str = "vmess";
/// Max length of each payload.
const MAX_PAYLOAD_LENGTH: usize = 16384; // 2 ^ 14

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum HeaderMode {
	Aead,
}

impl Default for HeaderMode {
	#[inline]
	fn default() -> Self {
		HeaderMode::Aead
	}
}

#[cfg(test)]
#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
mod tests {
	use super::*;
	use crate::test_utils::run_proxy_test;
	use inbound::{SettingsBuilder as InboundSettingsBuilder, User};
	use outbound::Settings as OutboundSettings;
	use std::str::FromStr;
	use uuid::Uuid;

	#[test]
	fn test_vmess() {
		let id = Uuid::from_str("b5b870f2-0efd-4980-a0a7-88a6bacb01d0").unwrap();
		let users = vec![User::new(id)];

		let args = vec![
			("vmess-none", SecurityType::None),
			("vmess-aes", SecurityType::Aes128Gcm),
			("vmess-chacha", SecurityType::Chacha20Poly1305),
		];

		for (tag, sec) in args {
			let inbound = InboundSettingsBuilder {
				users: users.clone(),
			}
			.build()
			.unwrap();
			run_proxy_test(tag.into(), inbound, |in_addr| {
				let mut outbound = OutboundSettings::new(in_addr, id);
				outbound.header_mode = HeaderMode::Aead;
				outbound.sec = sec;
				outbound
			});
		}
	}
}
