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

use md5::{Digest, Md5};
use uuid::Uuid;

const SALT: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";

fn next(id: &Uuid) -> Uuid {
	let mut md5 = Md5::new();
	md5.update(id.as_bytes());
	md5.update(SALT);
	let result = md5.finalize();
	return Uuid::from_slice(result.as_ref()).expect("Uuid bytes length must be 16");
}

pub(super) fn new(main_id: &Uuid, num_alter_ids: usize) -> Vec<Uuid> {
	let mut result = Vec::with_capacity(num_alter_ids);
	let mut prev_id = *main_id;
	for _ in 0..num_alter_ids {
		let new_id = next(&prev_id);
		debug_assert_ne!(&new_id, main_id);
		result.push(new_id);
		prev_id = new_id;
	}
	result
}
