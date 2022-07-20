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

use super::Empty;
use crate::protocol::AsyncReadWrite;
use std::io;

// -------------------------------------------------
//                   Inbound
// -------------------------------------------------

#[ladder_lib_macro::impl_variants(Inbound)]
mod settings {
	use crate::{protocol::AsyncReadWrite, transport};
	use std::io;
	use tokio::io::{AsyncRead, AsyncWrite};

	pub enum Inbound {
		None(transport::inbound::Empty),
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		Tls(transport::tls::Inbound),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		Ws(transport::ws::Inbound),
		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		H2(transport::h2::Inbound),
	}

	impl Inbound {
		#[implement(map_into_map_err_into)]
		pub async fn accept<IO>(&self, stream: IO) -> io::Result<Box<dyn AsyncReadWrite>>
		where
			IO: 'static
				+ AsyncRead
				+ AsyncWrite
				+ Unpin
				+ Send
				+ Sync
				+ Into<Box<dyn AsyncReadWrite>>,
		{
		}
	}
}
pub use settings::Inbound;

impl Inbound {
	#[inline]
	pub fn is_none(&self) -> bool {
		matches!(self, Self::None(_))
	}
}

impl Default for Inbound {
	fn default() -> Self {
		Self::None(Empty)
	}
}

// -------------------------------------------------
//                   Builder
// -------------------------------------------------

#[ladder_lib_macro::impl_variants(Builder)]
mod settings_builder {
	use super::Inbound;
	use crate::{prelude::BoxStdErr, protocol::DisplayInfo, transport};

	#[cfg_attr(test, derive(PartialEq, Eq))]
	#[derive(Debug, Clone)]
	#[cfg_attr(
		feature = "use_serde",
		derive(serde::Deserialize),
		serde(rename_all = "lowercase", tag = "type")
	)]
	pub enum Builder {
		None(transport::inbound::Empty),
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		Tls(transport::tls::InboundBuilder),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		Ws(transport::ws::InboundBuilder),
		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		H2(transport::h2::InboundBuilder),
	}

	impl Builder {
		#[implement(map_into_map_err_into)]
		pub fn build(self) -> Result<Inbound, BoxStdErr> {}
	}

	impl DisplayInfo for Builder {
		#[implement]
		fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {}
		#[implement]
		fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {}
	}
}

pub use settings_builder::Builder;

impl Default for Builder {
	fn default() -> Self {
		Builder::None(Empty)
	}
}

impl Builder {
	#[inline]
	#[must_use]
	pub fn is_empty(&self) -> bool {
		matches!(self, Self::None(_))
	}
}

#[allow(clippy::trivially_copy_pass_by_ref)]
#[allow(clippy::unnecessary_wraps)]
impl Empty {
	#[inline]
	pub async fn accept<IO>(&self, stream: IO) -> io::Result<Box<dyn AsyncReadWrite>>
	where
		IO: 'static + Into<Box<dyn AsyncReadWrite>>,
	{
		Ok(stream.into())
	}
}
