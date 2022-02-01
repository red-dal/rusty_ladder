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

use crate::{prelude::BoxStdErr, protocol::AsyncReadWrite};
use std::io;

#[ladder_lib_macro::impl_variants(Settings)]
mod settings {
	use crate::{protocol::AsyncReadWrite, transport};
	use std::io;
	use tokio::io::{AsyncRead, AsyncWrite};

	pub enum Settings {
		None(transport::inbound::Empty),
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		Tls(transport::tls::Inbound),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		Ws(transport::ws::Inbound),
		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		H2(transport::h2::Inbound),
	}

	impl Settings {
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
pub use settings::Settings;

impl Settings {
	#[inline]
	pub fn is_none(&self) -> bool {
		matches!(self, Self::None(_))
	}
}

impl Default for Settings {
	fn default() -> Self {
		Self::None(Empty)
	}
}

#[ladder_lib_macro::impl_variants(SettingsBuilder)]
mod settings_builder {
	use super::Settings;
	use crate::{prelude::BoxStdErr, transport};

	#[cfg_attr(test, derive(PartialEq, Eq))]
	#[derive(Debug, Clone)]
	#[cfg_attr(
		feature = "use_serde",
		derive(serde::Deserialize),
		serde(rename_all = "lowercase", tag = "type")
	)]
	pub enum SettingsBuilder {
		None(transport::inbound::Empty),
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		Tls(transport::tls::InboundBuilder),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		Ws(transport::ws::InboundBuilder),
		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		H2(transport::h2::InboundBuilder),
	}

	impl SettingsBuilder {
		#[implement(map_into_map_err_into)]
		pub fn build(self) -> Result<Settings, BoxStdErr> {}
	}
}

pub use settings_builder::SettingsBuilder;

impl Default for SettingsBuilder {
	fn default() -> Self {
		SettingsBuilder::None(Empty)
	}
}

#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct Empty;

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

	#[inline]
	fn build(self) -> Result<Self, BoxStdErr> {
		Ok(self)
	}
}
