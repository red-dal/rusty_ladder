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

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
#![allow(clippy::default_trait_access)]

// TODO:
// - Balancer
// - Clean up trait

mod non_zeros;
mod prelude;
mod transport;
mod utils;

pub mod network;
pub mod protocol;
pub mod proxy;
pub mod router;
pub mod server;

#[cfg(test)]
mod test_utils;

pub use server::{stat::Monitor, BuildError as ServerBuildError, Builder as ServerBuilder, Server};
pub use utils::BytesCount;

macro_rules! make_feature_str {
	($name: literal) => {
		#[cfg(feature = $name)]
		$name
	};
}

pub const FEATURES: &[&str] = &[
	make_feature_str!("local-dns"),
	make_feature_str!("local-dns-over-openssl"),
	make_feature_str!("local-dns-over-rustls"),
	make_feature_str!("use-udp"),
	make_feature_str!("use-webapi"),
	make_feature_str!("use-protobuf"),
	make_feature_str!("use-router-regex"),
	make_feature_str!("ws-transport-openssl"),
	make_feature_str!("tls-transport-openssl"),
	make_feature_str!("h2-transport-openssl"),
	make_feature_str!("ws-transport-rustls"),
	make_feature_str!("tls-transport-rustls"),
	make_feature_str!("h2-transport-rustls"),
	make_feature_str!("socks5-inbound"),
	make_feature_str!("socks5-outbound"),
	make_feature_str!("http-inbound"),
	make_feature_str!("http-outbound"),
	make_feature_str!("shadowsocks-inbound-openssl"),
	make_feature_str!("shadowsocks-outbound-openssl"),
	make_feature_str!("shadowsocks-inbound-ring"),
	make_feature_str!("shadowsocks-outbound-ring"),
	make_feature_str!("vmess-legacy-auth"),
	make_feature_str!("vmess-inbound-openssl"),
	make_feature_str!("vmess-outbound-openssl"),
	make_feature_str!("vmess-inbound-ring"),
	make_feature_str!("vmess-outbound-ring"),
	make_feature_str!("chain-outbound"),
	make_feature_str!("trojan-outbound"),
];
