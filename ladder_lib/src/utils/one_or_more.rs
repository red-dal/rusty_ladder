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

use std::{
	borrow::Borrow,
	fmt::{self, Display, Formatter},
	ops::Deref,
};

/// A container that does not use heap allocation when there is only one element.
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize), serde(untagged))]
pub enum OneOrMany<T> {
	#[cfg_attr(
		feature = "use_serde",
		serde(deserialize_with = "serde_internals::deserialize")
	)]
	One([T; 1]),
	Many(Vec<T>),
}

impl<T> OneOrMany<T> {
	#[inline]
	pub fn as_slice(&self) -> &[T] {
		match self {
			OneOrMany::One(v) => v.as_ref(),
			OneOrMany::Many(v) => v.as_slice(),
		}
	}

	#[inline]
	#[must_use]
	pub fn new_one(val: T) -> Self {
		Self::One([val])
	}
}

impl<T> Deref for OneOrMany<T> {
	type Target = [T];

	#[inline]
	fn deref(&self) -> &Self::Target {
		self.as_slice()
	}
}

impl<T> Borrow<[T]> for OneOrMany<T> {
	#[inline]
	fn borrow(&self) -> &[T] {
		self.as_slice()
	}
}

impl<T: Default> Default for OneOrMany<T> {
	fn default() -> Self {
		Self::One([T::default()])
	}
}

impl<T: Clone> Clone for OneOrMany<T> {
	fn clone(&self) -> Self {
		match self {
			OneOrMany::One(v) => Self::One(v.clone()),
			OneOrMany::Many(v) => Self::Many(v.clone()),
		}
	}
}

impl<T: Display> Display for OneOrMany<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			OneOrMany::One(val) => write!(f, "[{}]", val[0]),
			OneOrMany::Many(val) => {
				f.write_str("[")?;
				for v in val {
					v.fmt(f)?;
					f.write_str(",")?;
				}
				f.write_str("]")?;
				Ok(())
			}
		}
	}
}

impl<T: fmt::Debug> fmt::Debug for OneOrMany<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			Self::One(data) => fmt::Debug::fmt(data, f),
			Self::Many(data) => fmt::Debug::fmt(data, f),
		}
	}
}

impl<T> IntoIterator for OneOrMany<T> {
	type Item = T;
	type IntoIter = IntoIter<T>;

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		match self {
			OneOrMany::One(data) => IntoIter::One(Some(data)),
			OneOrMany::Many(data) => IntoIter::Many(data.into_iter()),
		}
	}
}

pub enum IntoIter<T> {
	One(Option<[T; 1]>),
	Many(<Vec<T> as IntoIterator>::IntoIter),
}

impl<T> Iterator for IntoIter<T> {
	type Item = T;

	fn next(&mut self) -> Option<Self::Item> {
		match self {
			IntoIter::One(data) => data.take().map(|d| {
				let [a] = d;
				a
			}),
			IntoIter::Many(iter) => iter.next(),
		}
	}
}

#[cfg(feature = "use_serde")]
mod serde_internals {
	pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<[T; 1], D::Error>
	where
		D: serde::Deserializer<'de>,
		T: serde::Deserialize<'de>,
	{
		T::deserialize(deserializer).map(|val| [val])
	}
}
