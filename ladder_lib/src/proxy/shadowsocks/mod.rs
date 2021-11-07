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
An implementation of shadowsocks protocol.
See more at <https://shadowsocks.org/en/wiki/Protocol.html>

Currently only supports AEAD ciphers.
Beware that GFW can probably detect and block foreign shadowsocks servers.
*/

#[cfg(any(feature = "shadowsocks-inbound-openssl", feature = "shadowsocks-inbound-ring"))]
pub mod inbound;
#[cfg(any(feature = "shadowsocks-outbound-openssl", feature = "shadowsocks-outbound-ring"))]
pub mod outbound;
mod tcp;
#[cfg(any(feature = "shadowsocks-outbound-openssl", feature = "shadowsocks-outbound-ring"))]
#[cfg(feature = "use-udp")]
mod udp;
mod utils;

pub use utils::Method;
use utils::{key_to_session_key, method_to_algo, password_to_key, Error};

pub const PROTOCOL_NAME: &str = "shadowsocks";

#[cfg(test)]
#[cfg(any(feature = "shadowsocks-inbound-openssl", feature = "shadowsocks-inbound-ring"))]
#[cfg(any(feature = "shadowsocks-outbound-openssl", feature = "shadowsocks-outbound-ring"))]
mod tests {
	use super::*;
	use crate::test_utils::run_proxy_test;
	use inbound::Settings as InboundSettings;
	use outbound::Settings as OutboundSettings;

	#[test]
	fn test_shadowsocks() {
		let password = "super-simple-password";

		let args = [
			("shadowsocks-aes-128", Method::Aes128Gcm),
			("shadowsocks-aes-256", Method::Aes256Gcm),
			("shadowsocks-chacha", Method::Chacha20Poly1305),
		];

		for (tag, method) in &args {
			let method = *method;
			let tag = *tag;
			let inbound = InboundSettings::new(password, method, Default::default());
			run_proxy_test(tag.into(), inbound, |in_addr| {
				OutboundSettings::new(in_addr, password, method, Default::default())
			});
		}
	}
}
