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

#[allow(unused_macros)]
/// Create a non-zero num type.
macro_rules! new {
	($val:expr, $nz_type:ty) => {{
		const __VAL: $nz_type = match <$nz_type>::new($val) {
			Some(v) => v,
			// Ugly hack to make compiler report error,
			// because compile time panic is not supported.
			#[deny(const_err)]
			None => [][($val == 0) as usize],
		};
		__VAL
	}};
}

#[allow(unused_macros)]
/// Create a [`std::num::NonZeroU8`].
///
/// This is a wrapper for `new!($val, NonZeroU8)`.
macro_rules! u8 {
	($val:expr) => {
		crate::non_zeros::new!($val, std::num::NonZeroU8)
	};
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn u8() {
		use std::num::NonZeroU8;
		assert_eq!(NonZeroU8::new(16).unwrap(), u8!(16));
		assert_eq!(NonZeroU8::new(1).unwrap(), u8!(1));
		assert_eq!(NonZeroU8::new(255).unwrap(), u8!(255));
		// This will cause compile error.
		// assert_eq!(NonZeroU8::new(0).unwrap(), u8!(0));

		// This will also cause compile error.
		// assert_eq!(NonZeroU8::new(256).unwrap(), u8!(256));
	}

	#[test]
	fn nz() {
		use std::num::NonZeroU8;
		assert_eq!(NonZeroU8::new(16).unwrap(), new!(16, NonZeroU8));
		assert_eq!(NonZeroU8::new(1).unwrap(), new!(1, NonZeroU8));
		assert_eq!(NonZeroU8::new(255).unwrap(), new!(255, NonZeroU8));
	}
}

#[allow(unused_imports)]
pub(crate) use {new, u8};
