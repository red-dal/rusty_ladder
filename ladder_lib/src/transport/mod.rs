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

#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
pub mod ws;

#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
pub mod tls;

#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
pub mod h2;

pub mod inbound;
pub use inbound::Inbound;

pub mod outbound;
pub use outbound::Outbound;

/// A dummy struct.
///
/// This is needed for using [`impl_variants`] macro.
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct Empty;

impl Empty {
	#[inline]
	#[allow(clippy::unnecessary_wraps)]
	fn build(self) -> Result<Self, crate::prelude::BoxStdErr> {
		Ok(self)
	}
}

impl crate::protocol::DisplayInfo for Empty {
	fn fmt_brief(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Do nothing
		Ok(())
	}

	fn fmt_detail(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		Ok(())
	}
}
