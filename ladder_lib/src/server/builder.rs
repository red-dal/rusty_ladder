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

use super::{inbound, outbound, Api, BuildError, Server};
use crate::{prelude::*, router};
use inbound::Inbound;
use outbound::Outbound;
use std::collections::HashMap;

#[cfg(feature = "local-dns")]
use super::dns;

#[derive(Debug, Default)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct Builder {
	pub inbounds: Vec<inbound::Builder>,
	pub outbounds: Vec<outbound::Builder>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub router: router::Builder,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub api: Api,
	#[cfg(feature = "local-dns")]
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub dns: Option<dns::Config>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub global: super::global::Builder,
}

impl Builder {
	/// Creates a [`Server`].
	///
	/// # Errors
	///
	/// Returns an error if any of the inbounds/outbounds or router failed to build.
	pub fn build(self) -> Result<Server, BuildError> {
		type Map = HashMap<Tag, usize>;
		// Returns false if tag already exists.
		// Empty tag will be ignored.
		fn add_tag(ind: usize, tag: &Tag, map: &mut Map, other_map: &Map) -> bool {
			tag.is_empty()
				|| (map.insert(tag.clone(), ind).is_none() && other_map.get(tag).is_none())
		}

		debug!("Server config: {:?}", self);

		let mut inbound_tags = HashMap::new();
		let mut outbound_tags = HashMap::new();

		for (ind, inbound) in self.inbounds.iter().enumerate() {
			if !add_tag(ind, &inbound.tag, &mut inbound_tags, &outbound_tags) {
				return Err(BuildError::InboundTagAlreadyExists {
					ind,
					tag: inbound.tag.clone(),
				});
			}
		}

		for (ind, outbound) in self.outbounds.iter().enumerate() {
			if !add_tag(ind, &outbound.tag, &mut outbound_tags, &inbound_tags) {
				return Err(BuildError::OutboundTagAlreadyExists {
					ind,
					tag: outbound.tag.clone(),
				});
			}
		}

		let router = {
			let find_inbound = |tag: &str| -> Option<usize> { inbound_tags.get(tag).copied() };
			let find_outbound = |tag: &str| -> Option<usize> { outbound_tags.get(tag).copied() };
			self.router.build(find_inbound, find_outbound)?
		};

		let inbounds: Result<Vec<Arc<Inbound>>, BuildError> = self
			.inbounds
			.into_iter()
			.enumerate()
			.map(|(ind, inbound_builder)| {
				inbound_builder
					.build()
					.map(Arc::new)
					.map_err(|err| BuildError::Inbound { ind, err })
			})
			.collect();
		let inbounds = inbounds?;

		let outbounds: Result<Vec<Outbound>, BuildError> = self
			.outbounds
			.into_iter()
			.enumerate()
			.map(|(ind, outbound_builder)| {
				outbound_builder
					.build()
					.map_err(|err| BuildError::Outbound { ind, err })
			})
			.collect();
		let outbounds = outbounds?;

		if let Api::WebApi { secret, addr: _ } = &self.api {
			if secret.is_empty() {
				return Err(BuildError::Api("web API secret cannot be empty".into()));
			}
		}

		Ok(Server {
			inbounds,
			outbounds,
			router,
			api: self.api,
			#[cfg(feature = "local-dns")]
			dns: self.dns,
			inbound_tags,
			outbound_tags,
			global: self.global.build()?,
		})
	}
}
