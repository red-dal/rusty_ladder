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

use crate::prelude::*;
#[allow(unused_imports)]
use crate::protocol::{ProxyContext, BytesStream};
use std::io;

#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
use super::ws;

#[cfg(feature = "browser-transport")]
use super::browser;

#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
use super::tls;

#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
use super::h2;

pub enum Settings {
	None,
	#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
	Tls(tls::Outbound),
	#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
	Ws(ws::Outbound),
	#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
	H2(h2::Outbound),
	#[cfg(feature = "browser-transport")]
	Browser(browser::Settings),
}

impl Default for Settings {
	fn default() -> Self {
		Self::None
	}
}

impl Settings {
	pub async fn connect_stream<'a>(
		&'a self,
		stream: BytesStream,
		#[allow(unused_variables)] addr: &'a SocksAddr,
	) -> io::Result<BytesStream> {
		Ok(match self {
			Settings::None => stream,
			#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
			Settings::Tls(s) => s.connect(stream, addr).await?.into(),
			#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
			Settings::Ws(s) => s.connect(stream, addr).await?.into(),
			#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
			Settings::H2(s) => s.connect(stream, addr).await?,
			#[cfg(feature = "browser-transport")]
			Settings::Browser(_) => {
				return Err(io::Error::new(
					io::ErrorKind::Other,
					"Cannot use browser transport layer in chain proxy.",
				));
			}
		})
	}

	pub async fn connect(
		&self,
		addr: &SocksAddr,
		context: &dyn ProxyContext,
	) -> io::Result<BytesStream> {
		debug!("Establishing transport connection to {}", addr);
		Ok(match self {
			Settings::None => context.dial_tcp(addr).await?.into(),
			#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
			Settings::Tls(s) => {
				let stream = context.dial_tcp(addr).await?;
				s.connect(stream, addr).await?.into()
			}
			#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
			Settings::Ws(s) => {
				let stream = context.dial_tcp(addr).await?;
				s.connect(stream, addr).await?.into()
			}
			#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
			Settings::H2(s) => {
				let stream = context.dial_tcp(addr).await?;
				s.connect(stream, addr).await?
			}
			#[cfg(feature = "browser-transport")]
			Settings::Browser(s) => s.connect(addr).await?.into(),
		})
	}
}

#[derive(Clone, Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(rename_all = "lowercase", tag = "type")
)]
pub enum SettingsBuilder {
	None,
	#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
	Tls(tls::OutboundBuilder),
	#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
	Ws(ws::OutboundBuilder),
	#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
	H2(h2::OutboundBuilder),
	#[cfg(feature = "browser-transport")]
	Browser(browser::SettingsBuilder),
}

impl SettingsBuilder {
	#[allow(clippy::unnecessary_wraps)]
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(match self {
			SettingsBuilder::None => Settings::None,
			#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
			SettingsBuilder::Tls(b) => Settings::Tls(b.build()?),
			#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
			SettingsBuilder::Ws(b) => Settings::Ws(b.build()?),
			#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
			SettingsBuilder::H2(b) => Settings::H2(b.build()?),
			#[cfg(feature = "browser-transport")]
			SettingsBuilder::Browser(b) => Settings::Browser(b.build()),
		})
	}
}

impl Default for SettingsBuilder {
	fn default() -> Self {
		SettingsBuilder::None
	}
}
