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

#[cfg(feature = "use-protobuf")]
#[allow(clippy::semicolon_if_nothing_returned)]
mod protos;

pub mod cidr;
pub use cidr::{Cidr, Cidr4, Cidr6};

mod rule;
pub use rule::{Destination, DestinationContainer, Error as RuleError, Plain as PlainRule, Rule};

use crate::protocol::SocksAddr;
use std::{
	fmt::{self, Display, Formatter},
	net::SocketAddr,
};

#[allow(unused_imports)]
use crate::prelude::BoxStdErr;

#[derive(Default)]
pub struct Router {
	pub rules: Vec<Rule>,
}

impl Router {
	#[must_use]
	pub fn choose_outbound(
		&self,
		inbound_ind: usize,
		src: &SocketAddr,
		dst: &SocksAddr,
	) -> Option<usize> {
		for rule in &self.rules {
			// check if traffic is from specific tag
			if rule.contains_inbound(inbound_ind)
				&& rule.src_hosts.contains(&src.ip())
				&& rule.contains_src_port(src.port())
				&& rule.contains_dst_port(dst.port)
				&& rule.dst_hosts.contains(&dst.dest)
			{
				return rule.outbound_ind;
			}
		}

		Some(0)
	}
}

#[derive(Default, Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Builder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub rules: Vec<PlainRule>,
}

impl Builder {
	/// Creates a new [`Router`].
	/// 
	/// # Errors
	/// 
	/// Returns [`Error`] if there are one or multiple rules contains error.
	pub fn build(
		self,
		find_inbound: impl Fn(&str) -> Option<usize>,
		find_outbound: impl Fn(&str) -> Option<usize>,
	) -> Result<Router, Error> {
		let mut result: Result<Router, Error> = Ok(Router { rules: Vec::new() });

		for (ind, pr) in self.rules.into_iter().enumerate() {
			let rule_result = pr.build(&find_inbound, &find_outbound);
			match &mut result {
				Ok(router) => match rule_result {
					Ok(r) => router.rules.push(r),
					Err(e) => result = Err(Error(vec![(ind, e)])),
				},
				Err(router_err) => {
					if let Err(e) = rule_result {
						router_err.0.push((ind, e));
					}
				}
			}
		}
		result
	}
}

/// A list of (position of the rule, [`RuleError`]).
#[derive(Debug)]
pub struct Error(pub Vec<(usize, RuleError)>);

impl Display for Error {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		write!(f, "[")?;
		for (ind, err) in &self.0 {
			write!(f, "rule {} ({}), ", ind, err)?;
		}
		write!(f, "]")
	}
}

impl std::error::Error for Error {}
