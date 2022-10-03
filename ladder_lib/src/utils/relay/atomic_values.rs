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

use std::sync::{
	atomic::{AtomicBool, AtomicU64, Ordering},
	Arc,
};

/// Wrapper for `Arc<AtomicU64>`.
#[derive(Clone)]
pub struct Counter(pub Arc<AtomicU64>);

impl Counter {
	#[inline]
	pub fn new(v: u64) -> Self {
		Self(Arc::new(AtomicU64::new(v)))
	}

	/// Returns the current value of the counter.
	#[inline]
	pub fn get(&self) -> u64 {
		self.0.load(Ordering::Relaxed)
	}

	/// Adds `v` into the counter and returns the old value.
	#[inline]
	pub fn add(&self, v: u64) -> u64 {
		self.0.fetch_add(v, Ordering::Relaxed)
	}
}

#[derive(Clone)]
pub struct Switch(pub Arc<AtomicBool>);

impl Switch {
	#[inline]
	pub fn new(v: bool) -> Self {
		Self(Arc::new(AtomicBool::new(v)))
	}

	#[inline]
	pub fn get(&self) -> bool {
		self.0.load(Ordering::Relaxed)
	}

	#[inline]
	pub fn set(&self, v: bool) {
		self.0.store(v, Ordering::Relaxed);
	}

	#[inline]
	pub fn fetch_and_set(&self, v: bool) -> bool {
		self.0.swap(v, Ordering::Relaxed)
	}
}
