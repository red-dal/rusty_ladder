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

use super::{super::crypto, kdf};
use crc::crc32;

// Auth ID in plain text:
// +-----------+------+------+
// | Timestamp | Rand | CRC  |
// +-----------+------+------+
// |    8B     |  4B  |  4B  |
// +-----------+------+------+
//
// Timestamp is the 64 bits unix timestamp.
// Rand is 4 bytes of random bytes.
// CRC is CRC32([Timestamp, Rand]).
//
// Auth ID is encrypted in AES-128 using key
// KDF(cmd_key, [AUTH_ID_ENCRYPTION])

/// See more at <https://github.com/v2fly/v2fly-github-io/issues/20>
const AUTH_ID_ENCRYPTION: &[u8] = b"AES Auth ID Encryption";

const AUTH_ID_LEN: usize = 16;
type AuthId = [u8; AUTH_ID_LEN];

#[allow(dead_code)]
pub fn new(cmd_key: &[u8; AUTH_ID_LEN], salt: [u8; 4], time: i64) -> AuthId {
	let mut auth_id = [0_u8; AUTH_ID_LEN];
	// Timestamp
	auth_id[..8].copy_from_slice(&time.to_be_bytes());
	// Rand
	auth_id[8..12].copy_from_slice(&salt);
	// CRC
	let crc_hash = crc32::checksum_ieee(&auth_id[..12]);
	auth_id[12..].copy_from_slice(&crc_hash.to_be_bytes());

	let key = kdf::new_16(cmd_key.as_ref(), [AUTH_ID_ENCRYPTION].iter().copied());
	let auth_id_ref = &mut auth_id;

	crypto::encrypt_aes_128(&key, auth_id_ref);
	auth_id
}

#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
mod inbound {
	use super::{crypto, kdf, AUTH_ID_ENCRYPTION};
	use crate::{proxy::vmess::utils::AuthId, utils::read_i64};
	use crc::crc32;
	use uuid::Uuid;

	/// Try to decrypt and extract timestamp from `auth_id`.
	/// Beware that timestamp might not be valid for current connection.
	///
	/// Return `Some(timestamp)` if checksum is matched after decryption.
	///
	/// Return `None` otherwise.
	fn decode(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> Option<i64> {
		let key = kdf::new_16(cmd_key.as_ref(), [AUTH_ID_ENCRYPTION].iter().copied());

		let mut auth_id = *auth_id;

		crypto::decrypt_aes_128(&key, &mut auth_id);

		let (data, hash) = auth_id.split_at(12);
		let expected_hash = crc32::checksum_ieee(data);

		if hash == expected_hash.to_be_bytes() {
			let time = read_i64(&auth_id[..8]);
			Some(time)
		} else {
			None
		}
	}

	/// Check `auth_id` with command keys and uuid of all users `users`.
	///
	/// Return `Some((uuid, cmd_key))` of the matched user.
	///
	/// Return `None` if there is no matched user.
	pub fn check<'a, Iter>(auth_id: &AuthId, users: Iter) -> Option<(&'a Uuid, &'a [u8; 16], i64)>
	where
		Iter: Iterator<Item = (&'a Uuid, &'a [u8; 16])>,
	{
		for (id, cmd_key) in users {
			log::trace!("Checking auth id for user {}", id);
			if let Some(time) = decode(cmd_key, auth_id) {
				return Some((id, cmd_key, time));
			}
		}
		None
	}

	#[cfg(test)]
	mod tests {
		use super::{super::new, *};
		use crate::{proxy::vmess::utils::new_cmd_key, utils::timestamp_now};
		use rand::Rng;
		use std::{convert::TryInto, str::FromStr};
		use uuid::Uuid;

		#[test]
		fn test_new_auth_id() {
			let expected = [
				159, 81, 84, 24, 248, 123, 183, 85, 58, 46, 106, 131, 222, 42, 138, 121,
			];
			let test_cmd_key = b"Demo Key for Auth ID Test"[..16].try_into().unwrap();
			let result = new(&test_cmd_key, [0, 1, 2, 3], 0);

			assert_eq!(result, expected);
		}

		#[test]
		fn test_decode_auth_id() {
			let time = timestamp_now();
			let cmd_key =
				new_cmd_key(&Uuid::from_str("1e562b2a-d1b3-41c0-8242-996e12b2a61a").unwrap());

			let auth_id = new(&cmd_key, rand::thread_rng().gen(), time);
			let result_time = decode(&cmd_key, &auth_id).unwrap();
			assert_eq!(result_time, time);

			let cmd_key =
				new_cmd_key(&Uuid::from_str("4b7de8c1-0a95-4abb-a13a-c298b14cbc71").unwrap());
			let result = decode(&cmd_key, &auth_id);
			assert!(result.is_none());
		}
	}
}

#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
pub use inbound::check;

#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
mod guarded_container {
	use super::AuthId;
	use crate::utils::timestamp_now;
	use futures::Future;
	use parking_lot::Mutex;
	use std::{
		collections::HashMap,
		convert::TryFrom,
		hash::Hash,
		sync::{
			atomic::{AtomicBool, Ordering},
			Arc,
		},
		time::Duration,
	};

	const UPDATE_INTERVAL: Duration = Duration::from_secs(1);

	const STOPPED: bool = true;
	const NOT_STOPPED: bool = !STOPPED;

	struct TimedSet<T: Eq + Hash> {
		pub max_diff: u64,
		data: HashMap<T, i64>,
	}

	impl<T: Eq + Hash> TimedSet<T> {
		#[inline]
		fn new(max_diff: u64) -> Self {
			Self {
				max_diff,
				data: HashMap::default(),
			}
		}

		/// Insert `item` with timestamp `time` into the container.
		///
		/// If `item` already exists, return `Some(old_time)`.
		///
		/// If `item` does not exist, return `None`.
		#[inline]
		fn insert(&mut self, item: T, curr_time: i64) -> Option<i64> {
			self.data.insert(item, curr_time)
		}

		/// Remove items whose time is not in `[curr_time - self.max_diff, curr_time + self.max_diff]`.
		fn clear(&mut self, curr_time: i64) {
			let max_diff = self.max_diff;
			self.data.retain(|_, time| {
				let diff = (curr_time - *time).abs();
				u64::try_from(diff).unwrap() <= max_diff
			});
			if self.data.is_empty() && self.data.capacity() == 0 {
				self.data.shrink_to_fit();
			}
		}
	}

	/// A container for storing [`AuthId`].
	#[derive(Clone)]
	struct Container {
		set: Arc<Mutex<TimedSet<AuthId>>>,
		is_stopped: Arc<AtomicBool>,
	}

	impl Drop for Container {
		fn drop(&mut self) {
			// Ignore error.
			self.is_stopped.store(STOPPED, Ordering::Relaxed);
		}
	}

	impl Container {
		/// Creates a new [`Container`] and a guard task.
		///
		/// The guard task must be polled in order to remove outdated auth id periodically.
		pub fn new(max_diff: u64) -> (Self, impl Future<Output = ()>) {
			let is_stopped = Arc::new(AtomicBool::new(NOT_STOPPED));
			let set = Arc::new(Mutex::new(TimedSet::new(max_diff)));
			let task = {
				let set = set.clone();
				let is_stopped = is_stopped.clone();
				async move {
					loop {
						if is_stopped.load(Ordering::Relaxed) == STOPPED {
							break;
						}
						tokio::time::sleep(UPDATE_INTERVAL).await;
						set.lock().clear(timestamp_now());
					}
				}
			};
			(Self { set, is_stopped }, task)
		}

		pub fn insert(&self, item: AuthId, curr_time: i64) -> Option<i64> {
			self.set.lock().insert(item, curr_time)
		}
	}

	#[derive(Clone)]
	enum WrapperInternal {
		Empty { max_diff: u64 },
		Initialized(Container),
	}

	pub struct GuardedContainer(Arc<Mutex<WrapperInternal>>);

	impl GuardedContainer {
		pub fn new(max_diff: u64) -> Self {
			Self(Arc::new(Mutex::new(WrapperInternal::Empty { max_diff })))
		}

		/// Insert `item` with timestamp `time` into the container.
		///
		/// If `item` already exists, return `Some(old_time)`.
		///
		/// If `item` does not exist, return `None`.
		pub async fn insert(&self, item: AuthId, curr_time: i64) -> Option<i64> {
			let mut c = self.0.lock();
			// The container is not initialized before calling insert.
			match &*c {
				WrapperInternal::Empty { max_diff } => {
					let (base, task) = Container::new(*max_diff);
					tokio::spawn(task);
					let res = base.insert(item, curr_time);
					*c = WrapperInternal::Initialized(base);
					res
				}
				WrapperInternal::Initialized(base) => base.insert(item, curr_time),
			}
		}
	}

	#[cfg(test)]
	mod tests {
		use super::{timestamp_now, TimedSet};

		#[test]
		fn test_timedset_insert() {
			let mut s = TimedSet::new(10);
			let curr_time = timestamp_now();
			assert_eq!(s.insert(1, curr_time), None);
			assert_eq!(s.insert(2, curr_time + 2), None);
			assert_eq!(s.insert(3, curr_time + 3), None);
			assert_eq!(s.insert(4, curr_time + 4), None);

			assert_eq!(s.insert(12, curr_time - 2), None);
			assert_eq!(s.insert(13, curr_time - 3), None);
			assert_eq!(s.insert(14, curr_time - 4), None);

			assert_eq!(s.insert(14, 0), Some(curr_time - 4));
			assert_eq!(s.insert(14, 1), Some(0));
			assert_eq!(s.insert(4, 1), Some(curr_time + 4));
		}

		#[test]
		fn test_timeset_clear() {
			let mut s = TimedSet::new(10);
			let curr_time = timestamp_now();
			assert_eq!(s.insert(1, curr_time), None);
			assert_eq!(s.insert(2, curr_time + 2), None);
			assert_eq!(s.insert(4, curr_time + 14), None);
			assert_eq!(s.insert(5, curr_time + 15), None);

			assert_eq!(s.insert(12, curr_time - 2), None);
			assert_eq!(s.insert(14, curr_time - 14), None);
			assert_eq!(s.insert(15, curr_time - 15), None);

			s.clear(curr_time);

			let mut result = s.data.into_iter().collect::<Vec<_>>();
			result.sort_by_key(|(_val, time)| *time);
			assert_eq!(
				result,
				[(12, curr_time - 2), (1, curr_time), (2, curr_time + 2)]
			);
		}
	}
}

#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
pub use guarded_container::GuardedContainer;
