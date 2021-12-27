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

mod api;
mod builder;
#[cfg(feature = "local-dns")]
pub mod dns;
mod error;
pub mod inbound;
pub mod outbound;
mod proxy_context;
mod serve;
pub mod stat;
#[cfg(feature = "use-udp")]
mod udp;

pub use api::Api;
pub use builder::{BuildError, Builder};
pub use error::Error;
pub use inbound::Inbound;
pub use outbound::Outbound;

use crate::{
	prelude::*,
	router::{PlainRule, Router, RuleError},
	Monitor,
};
use std::{borrow::Cow, collections::HashMap, sync::Arc, time::Duration};

#[derive(Default)]
pub struct Server {
	pub inbounds: Vec<Inbound>,
	pub outbounds: Vec<Outbound>,
	pub router: Router,
	pub api: Api,
	inbound_tags: HashMap<Tag, usize>,
	outbound_tags: HashMap<Tag, usize>,
	#[cfg(feature = "local-dns")]
	pub dns: Option<dns::Config>,
	// Timeouts
	/// TCP connection will be dropped if it cannot be established within this amount of time.
	dial_tcp_timeout: Duration, 
	outbound_handshake_timeout: Duration,
	relay_timeout_secs: usize,
	#[cfg(feature = "use-udp")]
	udp_session_timeout: Duration,
}

impl Server {
	/// Creates a new server.
	///
	/// # Errors
	///
	/// Will return `Err` if there are any duplicate tag in `inbounds` or `outbounds`.
	pub fn new(
		inbounds: Vec<Inbound>,
		outbounds: Vec<Outbound>,
	) -> Result<Self, Cow<'static, str>> {
		fn process(
			map: &mut HashMap<Tag, usize>,
			tag: &Tag,
			ind: usize,
			location: &'static str,
		) -> Result<(), Cow<'static, str>> {
			if tag.is_empty() {
				return Ok(());
			}
			if map.insert(tag.clone(), ind).is_none() {
				Ok(())
			} else {
				Err(format!("tag '{}' on {} {} already exists ", tag, location, ind).into())
			}
		}

		let mut res = Self {
			inbounds,
			..Server::default()
		};
		for (ind, inbound) in res.inbounds.iter_mut().enumerate() {
			process(&mut res.inbound_tags, &inbound.tag, ind, "inbound")?;
		}

		res.outbounds = outbounds;
		for (ind, outbound) in res.outbounds.iter_mut().enumerate() {
			process(&mut res.outbound_tags, &outbound.tag, ind, "outbound")?;
		}

		Ok(res)
	}

	/// Adds a rule into the server router.
	///
	/// # Errors
	///
	/// Will return `Err` if `plain_rule` is invalid
	pub fn add_rule(&mut self, plain_rule: PlainRule) -> Result<(), RuleError> {
		let r = plain_rule.build(
			|tag| self.inbound_tags.get(tag).copied(),
			|tag| self.outbound_tags.get(tag).copied(),
		)?;
		self.router.rules.push(r);
		Ok(())
	}

	/// Start running the server.
	///
	/// If `monitor` is not None, it will be used to monitor all sessions in this server.
	///
	/// # Errors
	///
	/// Returns an error if there are any inbound that failed to initialized.
	///
	/// After initializing all inbounds, all session errors will only be logged.
	pub async fn serve(self: Arc<Self>, monitor: Option<Monitor>) -> Result<(), BoxStdErr> {
		self.priv_serve(monitor).await
	}

	#[must_use]
	pub fn get_inbound(&self, tag: &str) -> Option<&Inbound> {
		self.inbound_tags.get(tag).map(|ind| &self.inbounds[*ind])
	}

	#[must_use]
	pub fn get_outbound(&self, tag: &str) -> Option<&Outbound> {
		self.outbound_tags.get(tag).map(|ind| &self.outbounds[*ind])
	}

	#[inline]
	#[must_use]
	pub fn default_outbound(&self) -> &Outbound {
		&self.outbounds[0]
	}
}
