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

use bytes::BufMut;
use md5::Digest;
use sha2::Sha224;

pub const PROTOCOL_NAME: &str = "trojan";

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

fn password_to_hex(password: &[u8], buf: &mut impl BufMut) {
	let mut hasher = Sha224::new();
	hasher.update(password);
	let hash = hasher.finalize();
	let hex = format!("{:056x}", hash);
	buf.put_slice(hex.as_bytes());
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
