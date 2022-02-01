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

#[cfg(feature = "socks5-inbound")]
pub mod inbound;
#[cfg(feature = "socks5-outbound")]
pub mod outbound;
mod utils;

pub use utils::Error;

pub const PROTOCOL_NAME: &str = "socks5";

#[cfg(test)]
#[cfg(feature = "socks5-inbound")]
#[cfg(feature = "socks5-outbound")]
mod tests {
	use super::*;
	use crate::{test_utils::run_proxy_test, transport};
	use inbound::Settings as InboundSettings;
	use outbound::Settings as OutboundSettings;

	#[test]
	fn test_socks5() {
		let inbound = InboundSettings::new_no_auth(transport::inbound::Settings::default());
		run_proxy_test("socks5".into(), inbound, |in_addr| {
			OutboundSettings::new_no_auth(in_addr, transport::outbound::Settings::default())
		});
	}

	#[test]
	fn test_socks5_auth() {
		let users = vec![("Hello", "World"), ("a", "b"), ("aa", "bb")];
		let users = users
			.into_iter()
			.map(|(user, pass)| (user.to_owned(), pass.to_owned()));
		let inbound = InboundSettings::new(users, Default::default());
		run_proxy_test("socks5-auth".into(), inbound, |in_addr| {
			OutboundSettings::new(Some(("a".into(), "b".into())), in_addr, Default::default())
		});
	}
}
