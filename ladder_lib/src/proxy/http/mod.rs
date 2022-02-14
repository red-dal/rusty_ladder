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

mod utils;

#[cfg(feature = "http-inbound")]
pub mod inbound;
#[cfg(feature = "http-outbound")]
pub mod outbound;

pub use utils::Error;
pub const PROTOCOL_NAME: &str = "http";

const MAX_BUFFER_SIZE: usize = 8 * 1024;

#[cfg(test)]
#[cfg(feature = "http-inbound")]
#[cfg(feature = "http-outbound")]
mod tests {
	use super::*;
	use crate::test_utils::run_proxy_test;
	use inbound::Settings as InboundSettings;
	use outbound::Settings as OutboundSettings;

	#[test]
	fn test_http() {
		let inbound = InboundSettings::new(vec![]);
		run_proxy_test("http".into(), inbound, |in_addr| {
			OutboundSettings::new_no_auth(in_addr)
		});
	}

	#[test]
	fn test_http_auth() {
		let users = vec![
			("user1", "pass2"),
			("user2", "pass2"),
			("user2", "pass2"),
			("a", "b"),
			("aa", "bb"),
		];
		let inbound = InboundSettings::new(users);
		run_proxy_test("http-auth".into(), inbound, |in_addr| {
			OutboundSettings::new("a", "b", in_addr)
		});
	}
}
