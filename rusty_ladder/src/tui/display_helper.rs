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

use std::fmt::{self, Display, Formatter};

pub(super) struct SecondsCount(pub u64);

impl Display for SecondsCount {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		let time = self.0;

		let sec_part = time % 60;
		let time = time / 60;

		let min_part = time % 60;
		let time = time / 60;

		let hour_part = time;

		if hour_part > 0 {
			write!(f, "{}h", hour_part)?;
		}
		if min_part > 0 {
			write!(f, "{}m", min_part)?;
		}
		write!(f, "{}s", sec_part)?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_format_duration() {
		assert_eq!(format!("{}", SecondsCount(0)), "0s");
		assert_eq!(format!("{}", SecondsCount(60)), "1m0s");
		assert_eq!(format!("{}", SecondsCount(70)), "1m10s");
		assert_eq!(format!("{}", SecondsCount(3600)), "1h0s");
		assert_eq!(format!("{}", SecondsCount(3601)), "1h1s");
		assert_eq!(format!("{}", SecondsCount(3661)), "1h1m1s");
	}
}
