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

use super::super::utils::new_auth;
use super::{User, UserInfo};
use crate::{prelude::*, utils::timestamp_now};
use std::{collections::HashMap, time::Duration};
use tokio::time::sleep;
use uuid::Uuid;

/// How many seconds to cache in each [`UserValidator`] updates.
const CACHE_DURATION_SECS: u64 = 120;

/// How many seconds to wait between each [`UserValidator`] updates.
const UPDATE_SECS: u64 = CACHE_DURATION_SECS / 2 - 1;

/// Helper struct for validating non-AEAD users.
pub struct UserValidator {
	data: HashMap<[u8; 16], UserInfo>,
}

impl UserValidator {
	pub fn new<'a, I>(timestamp: i64, users: I) -> Self
	where
		I: Iterator<Item = &'a User>,
	{
		let mut res = Self {
			data: HashMap::default(),
		};

		res.update(timestamp, users);

		res
	}

	pub fn update<'a, I>(&mut self, timestamp: i64, users: I)
	where
		I: Iterator<Item = &'a User>,
	{
		#[allow(clippy::cast_possible_wrap)]
		const DELTA_SECS: i64 = (CACHE_DURATION_SECS / 2) as i64;

		self.data.clear();

		let begin_secs = timestamp - DELTA_SECS;
		let end_secs = timestamp + DELTA_SECS + 1;

		let mut update_id = |time: i64, id: &Uuid, user: &User| {
			let auth = new_auth(time, id)
				.expect("Programming error: cannot calculate auth for UserValidator");
			let info = UserInfo {
				id: user.id,
				cmd_key: user.cmd_key,
				time,
			};
			self.data.insert(auth, info);
		};

		for user in users {
			if let super::AlterId::Legacy(alter_ids) = &user.alter_ids {
				for time in begin_secs..end_secs {
					// Update main ID
					update_id(time, &user.id, user);

					// Update alternative IDs
					for alter_id in alter_ids {
						update_id(time, alter_id, user);
					}
				}
			}
		}
	}

	pub(super) fn get<'a>(&'a self, auth: &[u8; 16]) -> Option<&'a UserInfo> {
		if let Some(info) = self.data.get(auth) {
			return Some(info);
		}
		None
	}
}

pub fn spawn_update_task(validator: Arc<AsyncMutex<UserValidator>>, users: Vec<User>) {
	tokio::spawn(async move {
		let update_duration = Duration::from_secs(UPDATE_SECS);
		loop {
			sleep(update_duration).await;
			validator.lock().await.update(timestamp_now(), users.iter());
		}
	});
}
