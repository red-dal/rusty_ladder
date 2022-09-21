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

use std::fmt;

/// Display bytes number in human readable form.
#[derive(Clone, Copy)]
pub struct BytesCount(pub u64);

impl fmt::Display for BytesCount {
	#[allow(clippy::cast_possible_truncation)]
	#[allow(clippy::cast_precision_loss)]
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		const BASE: u64 = 1024;
		const NAMES: &[&str] = &["KiB", "MiB", "GiB"];
		let num = self.0;
		if num < BASE {
			write!(f, "{}B", num)
		} else {
			let num = num as f64;
			// Because num >= 1024, log2(num) >= 10,
			// and because num < 2^64, log2(num) < 64
			let index = num.log2() / 10.0 - 1.0;
			#[allow(clippy::cast_sign_loss)]
			let index = std::cmp::min(index as usize, NAMES.len() - 1);
			let value = num / (BASE.pow(index as u32 + 1) as f64);
			write!(f, "{:.2}{}", value, NAMES[index])
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn bytes_count_display() {
		const KIB: u64 = 1024;
		const MIB: u64 = KIB * 1024;
		const GIB: u64 = MIB * 1024;

		assert_eq!(BytesCount(0).to_string(), "0B");
		assert_eq!(BytesCount(1).to_string(), "1B");
		assert_eq!(BytesCount(25).to_string(), "25B");
		assert_eq!(BytesCount(512).to_string(), "512B");
		assert_eq!(BytesCount(1023).to_string(), "1023B");

		assert_eq!(BytesCount(KIB).to_string(), "1.00KiB");
		assert_eq!(BytesCount(1536).to_string(), "1.50KiB");
		assert_eq!(BytesCount(2 * KIB).to_string(), "2.00KiB");
		assert_eq!(BytesCount(8888).to_string(), "8.68KiB");
		assert_eq!(BytesCount(9 * KIB).to_string(), "9.00KiB");

		assert_eq!(BytesCount(MIB).to_string(), "1.00MiB");
		assert_eq!(BytesCount(1536 * KIB).to_string(), "1.50MiB");
		assert_eq!(BytesCount(2 * MIB).to_string(), "2.00MiB");
		assert_eq!(
			BytesCount((1.22 * MIB as f64) as u64).to_string(),
			"1.22MiB"
		);
		assert_eq!(
			BytesCount((4.33 * MIB as f64) as u64).to_string(),
			"4.33MiB"
		);
		assert_eq!(
			BytesCount((9.99 * MIB as f64) as u64).to_string(),
			"9.99MiB"
		);

		assert_eq!(BytesCount(GIB).to_string(), "1.00GiB");
		assert_eq!(
			BytesCount((9.99 * GIB as f64) as u64).to_string(),
			"9.99GiB"
		);
		assert_eq!(
			BytesCount((19.99 * GIB as f64) as u64).to_string(),
			"19.99GiB"
		);
		assert_eq!(
			BytesCount((12345.11 * GIB as f64) as u64).to_string(),
			"12345.11GiB"
		);
	}
}
