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
Implementation of the trojan krotocol,
see more at <https://trojan-gfw.github.io/trojan/protocol.html>

But this implementation does not include a security layer such as TLS.
DO NOT use this without a security layer over an unsecure network.

Trojan request format:
```not_rust
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+
```

where target address is a SOCKS5 address:
```not_rust
+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+
```

See more about SOCKS5 address at <https://tools.ietf.org/html/rfc1928#section-5>
*/

use md5::Digest;
use sha2::Sha224;

pub const PROTOCOL_NAME: &str = "trojan";

type Key = [u8; 56];

#[cfg(feature = "trojan-outbound")]
pub mod outbound;
#[cfg(feature = "trojan-inbound")]
pub mod inbound;

#[repr(u8)]
enum Command {
	Connect = 0x1,
	#[cfg(feature = "use-udp")]
	UdpAssociate = 0x3,
}

impl Command {
	fn from_u8(v: u8) -> Option<Self> {
		const CONNECT: u8 = Command::Connect as u8;
		#[cfg(feature = "use-udp")]
		const UDP_ASSOCIATE: u8 = Command::UdpAssociate as u8;

		Some(match v {
			CONNECT => Command::Connect,
			#[cfg(feature = "use-udp")]
			UDP_ASSOCIATE => Command::UdpAssociate,
			_ => return None,
		})
	}
}

fn sha_then_hex(password: &[u8]) -> Key {
	const TABLE: [u8; 16] = [
		b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e',
		b'f',
	];

	let mut hasher = Sha224::new();
	hasher.update(password);

	let hash: [u8; 28] = hasher.finalize().into();
	let mut result = [0u8; 56];

	for (&b, out) in hash.iter().zip(result.chunks_mut(2)) {
		let high = b >> 4;
		let low = b & 0x0f;
		out[0] = TABLE[high as usize];
		out[1] = TABLE[low as usize];
	}

    result
}

#[cfg(feature = "trojan-outbound")]
#[cfg(feature = "trojan-inbound")]
#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_utils::run_proxy_test;

	#[test]
	fn test_proxy() {
		let inb = inbound::SettingsBuilder {
			passwords: ["password".into()].into(),
			redir_addr: "127.0.0.1:2929".parse().unwrap(),
		}
		.build()
		.unwrap();
		run_proxy_test("trojan".into(), inb, |in_addr| {
			outbound::SettingsBuilder {
				password: "password".into(),
				addr: in_addr,
			}
			.build()
			.unwrap()
		});
	}
}
