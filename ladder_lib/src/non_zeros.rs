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

use lazy_static::lazy_static;
use std::num::{NonZeroU16, NonZeroU8};

macro_rules! make_nonzero {
	($t:ty, $name:ident, $val:literal) => {
		lazy_static! {
			pub static ref $name: $t = <$t>::new($val).unwrap();
		}
	};
}

macro_rules! make_u8 {
	($name:ident, $val:literal) => {
		make_nonzero!(NonZeroU8, $name, $val);
	};
}

macro_rules! make_u16 {
	($name:ident, $val:literal) => {
		make_nonzero!(NonZeroU16, $name, $val);
	};
}

make_u8!(U8_1, 1_u8);
make_u8!(U8_2, 2_u8);
make_u8!(U8_4, 4_u8);
make_u8!(U8_6, 6_u8);
make_u8!(U8_8, 8_u8);
make_u8!(U8_10, 10_u8);
make_u8!(U8_12, 12_u8);
make_u8!(U8_16, 16_u8);
make_u8!(U8_18, 18_u8);
make_u8!(U8_32, 32_u8);
make_u8!(U8_64, 64_u8);
make_u8!(U8_128, 128_u8);

make_u16!(U16_256, 256_u16);
make_u16!(U16_512, 512_u16);

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_nums() {
		assert_eq!(U8_1.get(), 1_u8);
		assert_eq!(U8_2.get(), 2_u8);
		assert_eq!(U8_4.get(), 4_u8);
		assert_eq!(U8_6.get(), 6_u8);
		assert_eq!(U8_8.get(), 8_u8);
		assert_eq!(U8_10.get(), 10_u8);
		assert_eq!(U8_12.get(), 12_u8);
		assert_eq!(U8_16.get(), 16_u8);
		assert_eq!(U8_18.get(), 18_u8);
		assert_eq!(U8_32.get(), 32_u8);
		assert_eq!(U8_64.get(), 64_u8);
		assert_eq!(U16_256.get(), 256_u16);
		assert_eq!(U16_512.get(), 512_u16);
	}
}
