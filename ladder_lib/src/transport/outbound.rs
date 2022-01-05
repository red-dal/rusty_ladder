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

#[allow(unused_imports)]
use crate::protocol::ProxyContext;
use crate::{prelude::*, protocol::AsyncReadWrite};
use std::io;

#[ladder_lib_macro::impl_variants(Settings)]
mod settings {
	use super::Empty;
	use crate::protocol::{AsyncReadWrite, ProxyContext, SocksAddr};
	use std::io;
	use tokio::io::{AsyncRead, AsyncWrite};

	pub enum Settings {
		None(Empty),
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		Tls(super::super::tls::Outbound),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		Ws(super::super::ws::Outbound),
		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		H2(super::super::h2::Outbound),
		#[cfg(feature = "browser-transport")]
		Browser(super::super::browser::Settings),
	}

	impl Settings {
		#[implement(map_into)]
		pub async fn connect_stream<'a, IO>(
			&'a self,
			stream: IO,
			#[allow(unused_variables)] addr: &'a SocksAddr,
		) -> io::Result<Box<dyn AsyncReadWrite>>
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

		#[implement(map_into)]
		pub async fn connect(
			&self,
			addr: &SocksAddr,
			context: &dyn ProxyContext,
		) -> io::Result<Box<dyn AsyncReadWrite>> {
		}
	}
}

pub use settings::Settings;

impl Default for Settings {
	fn default() -> Self {
		Self::None(Empty)
	}
}

#[ladder_lib_macro::impl_variants(SettingsBuilder)]
mod settings_builder {
	use super::{Empty, Settings};
	use crate::prelude::BoxStdErr;

	#[derive(Clone, Debug)]
	#[cfg_attr(
		feature = "use_serde",
		derive(serde::Deserialize),
		serde(rename_all = "lowercase", tag = "type")
	)]
	pub enum SettingsBuilder {
		None(Empty),
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		Tls(super::super::tls::OutboundBuilder),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		Ws(super::super::ws::OutboundBuilder),
		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		H2(super::super::h2::OutboundBuilder),
		#[cfg(feature = "browser-transport")]
		Browser(super::super::browser::SettingsBuilder),
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

#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct Empty;

#[allow(clippy::trivially_copy_pass_by_ref)]
#[allow(clippy::unnecessary_wraps)]
impl Empty {
	#[inline]
	pub async fn connect(
		&self,
		addr: &SocksAddr,
		context: &dyn ProxyContext,
	) -> io::Result<Box<dyn AsyncReadWrite>> {
		self.connect_stream(context.dial_tcp(addr).await?, addr)
			.await
			.map(Into::into)
	}

	#[inline]
	pub async fn connect_stream<IO>(&self, stream: IO, _addr: &SocksAddr) -> io::Result<IO>
	where
		IO: AsyncRead + AsyncWrite + Unpin,
	{
		Ok(stream)
	}

	#[inline]
	fn build(self) -> Result<Self, BoxStdErr> {
		Ok(self)
	}
}