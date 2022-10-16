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

use super::{args::ActionCommons, config, BoxStdErr, Config, Error};
use ladder_lib::{router, server};
use log::LevelFilter;
use std::str::FromStr;
use url::Url;

const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Info;

/// Make [`Config`] with arguments like `--inbound`, `--outbound`.
pub(super) fn make_config_from_args(
	in_url: &str,
	out_url: &str,
	allow_lan: bool,
	block_list: &[String],
	coms: ActionCommons,
) -> Result<Config, Error> {
	let rules = make_blocklist(allow_lan, block_list.iter().map(String::as_str))?;

	let inbound = {
		let url = in_url;
		let func = || -> Result<_, BoxStdErr> {
			if url.is_empty() {
				return Err("empty string".into());
			}
			let builder = server::inbound::Builder::parse_url(&Url::from_str(url)?)?;
			Ok(builder)
		};
		func().map_err(|e| Error::input(format!("cannot parse inbound ({e})")))?
	};
    
	let outbound = {
		let url = out_url;
		let func = || -> Result<_, BoxStdErr> {
			if url.is_empty() {
				return Err("empty string".into());
			}
			if url == "freedom" {
				return Ok(server::outbound::Builder::new_freedom());
			}
			let builder = server::outbound::Builder::parse_url(&Url::from_str(url)?)?;
			Ok(builder)
		};
		func().map_err(|e| Error::input(format!("cannot parse outbound ({e})")))?
	};

	let config = Config {
		log: config::Log {
			level: coms.log.unwrap_or(DEFAULT_LOG_LEVEL),
			output: coms.log_out,
		},
		server: server::Builder {
			inbounds: vec![inbound],
			outbounds: vec![outbound],
			router: router::Builder { rules },
			..Default::default()
		},
	};

	Ok(config)
}

fn make_blocklist<'a>(
	allow_lan: bool,
	block_list: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<ladder_lib::router::PlainRule>, Error> {
	const LAN_STR: &str = "@lan";
	const LOCALHOST_STR: &str = "@localhost";

	use ladder_lib::protocol::socks_addr::DomainName;
	use router::{Cidr, Destination};

	fn push_lan(buf: &mut Vec<Destination>) {
		buf.extend(
			Vec::from(Cidr::private_networks())
				.into_iter()
				.map(Destination::Cidr),
		);
	}

	fn push_localhost(buf: &mut Vec<Destination>) {
		buf.push(Destination::Cidr(router::Cidr4::LOCALLOOP.into()));
		buf.push(Destination::Cidr(router::Cidr6::LOCALLOOP.into()));
	}

	let mut dsts = Vec::<Destination>::with_capacity(16);

	if !allow_lan {
		push_lan(&mut dsts);
		push_localhost(&mut dsts);
	}

	for part in block_list {
		match part {
			LAN_STR => push_lan(&mut dsts),
			LOCALHOST_STR => push_localhost(&mut dsts),
			_ => {
				if let Ok(ip) = std::net::IpAddr::from_str(part) {
					dsts.push(Destination::Ip(ip));
				} else if let Ok(name) = DomainName::from_str(part) {
					dsts.push(Destination::Domain(name));
				} else if let Ok(cidr) = Cidr::from_str(part) {
					dsts.push(Destination::Cidr(cidr));
				} else {
					return Err(Error::input(format!(
						"'{}' is not a valid IP or domain",
						part
					)));
				}
			}
		}
	}

	dsts.shrink_to_fit();
	Ok(if dsts.is_empty() {
		Vec::new()
	} else {
		vec![router::PlainRule {
			dsts,
			outbound_tag: None,
			..Default::default()
		}]
	})
}
