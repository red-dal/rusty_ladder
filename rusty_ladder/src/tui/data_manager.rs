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

use super::ColumnIndex;
use ladder_lib::server::stat::{self, snapshot, Monitor, Snapshot};
use log::trace;
use std::cmp::Ordering;
use tokio::runtime::Handle;

pub(super) struct DataManager {
	monitor: Monitor,
	pub snapshots: Vec<Snapshot>,
	rt: Handle,
}

impl DataManager {
	pub fn new(rt: Handle, monitor: Monitor) -> Self {
		Self {
			monitor,
			snapshots: Vec::with_capacity(64),
			rt,
		}
	}

	pub fn update(&mut self) {
		trace!("Querying data for TUI");
		{
			let result = &mut self.snapshots;
			let monitor = &self.monitor;
			self.rt.block_on(async {
				// call async functions
				monitor.query(&stat::Filter::new_all(), result);
			});
		}
	}

	pub fn row_count(&self) -> usize {
		self.snapshots.len()
	}

	pub fn sort(&mut self, col: Option<ColumnIndex>) {
		trace!("Sorting data");

		self.snapshots
			.sort_by(|a, b| compare_with_column(a, b, col).reverse());

		trace!("Updating selection position");
	}

	pub fn snapshots(&self) -> impl Iterator<Item = &Snapshot> {
		self.snapshots.iter()
	}
}

fn cmp_with<'a, T, F, R>(a: &'a T, b: &'a T, func: F) -> Ordering
where
	F: Fn(&'a T) -> R,
	R: Ord + 'a,
{
	let a = func(a);
	let b = func(b);
	a.cmp(&b)
}

/// Compares snapshot `a` and `b` with specific column `col`.
///
/// If `col` is `None`, compares `a` and `b` with their start times.
fn compare_with_column(a: &Snapshot, b: &Snapshot, col: Option<ColumnIndex>) -> Ordering {
	let end_times = match (a.end_time, b.end_time) {
		(None, Some(_)) => {
			// a alive, b dead
			return Ordering::Greater;
		}
		(Some(_), None) => {
			// a dead, b alive
			return Ordering::Less;
		}
		(None, None) => None,
		(Some(a_end_time), Some(b_end_time)) => Some((a_end_time, b_end_time)),
	};

	// a and b are both dead or both alive
	let col = if let Some(col) = col {
		col
	} else {
		return cmp_with(a, b, |item| item.basic.start_time);
	};

	match col {
		ColumnIndex::ConnId => cmp_with(a, b, |item| &item.basic.conn_id),
		ColumnIndex::Inbound => cmp_with(a, b, |item| &item.basic.inbound_tag),
		ColumnIndex::Outbound => cmp_with(a, b, |item| {
			item.outbound_tag().map_or("", smol_str::SmolStr::as_str)
		}),
		ColumnIndex::Dst => cmp_with(a, b, Snapshot::to),
		ColumnIndex::Recv => cmp_with(a, b, Snapshot::recv),
		ColumnIndex::Send => cmp_with(a, b, Snapshot::send),
		ColumnIndex::Lasted => {
			if let Some((a_end_time, b_end_time)) = end_times {
				let a_lasted = a_end_time
					.duration_since(a.basic.start_time)
					.expect("Invalid system time");
				let b_lasted = b_end_time
					.duration_since(b.basic.start_time)
					.expect("Invalid system time");
				a_lasted.cmp(&b_lasted)
			} else {
				// The greater value lasts longer,
				// so the result of comparing start_time must be reversed.
				cmp_with(a, b, |item| item.basic.start_time).reverse()
			}
		}
		ColumnIndex::State => cmp_with(a, b, |item| match &item.state {
			snapshot::State::Handshaking => 0,
			snapshot::State::Connecting(_) => 1,
			snapshot::State::Proxying {
				out: _,
				recv: _,
				send: _,
				recv_speed: _,
				send_speed: _,
			} => 2,
		}),
		ColumnIndex::ColNum => {
			// do nothing
			panic!("Invalid column. Please make sure that column is valid.");
		}
	}
}
