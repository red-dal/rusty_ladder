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

const KB: (&str, u64) = ("KB", 1024);
const MB: (&str, u64) = ("MB", KB.1 * 1024);
const GB: (&str, u64) = ("GB", MB.1 * 1024);

const BYTE_BASES: &[(&str, u64)] = &[GB, MB, KB];

#[derive(Clone, Copy)]
pub struct BytesCount(pub u64);

impl fmt::Display for BytesCount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let num = self.0;
		for &(base_name, base) in BYTE_BASES {
			// check number against each base
			if num >= base {
				#[allow(clippy::cast_precision_loss)]
				let res_num = (num as f64) / (base as f64);
				return write!(f, "{:.2} {}", res_num, base_name);
			}
		}
		write!(f, "{} B", num)
	}
}
