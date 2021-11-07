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

use crate::prelude::BoxStdErr;
#[allow(unused_imports)]
use crate::protocol::BytesStream;
use std::io;

#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
use super::ws;

#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
use super::tls;

#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
use super::h2;

pub enum Settings {
	None,
	#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
	Tls(tls::Inbound),
	#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
	Ws(ws::Inbound),
	#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
	H2(h2::Inbound),
}

impl Default for Settings {
	fn default() -> Self {
		Self::None
	}
}

impl Settings {
	pub async fn accept(&self, stream: BytesStream) -> io::Result<BytesStream> {
		Ok(match self {
			Settings::None => stream,
			#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
			Settings::Tls(s) => s.accept(stream).await?.into(),
			#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
			Settings::Ws(s) => s.accept(stream).await?.into(),
			#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
			Settings::H2(s) => s.accept(stream).await?,
		})
	}
}

#[derive(Debug, Clone)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(rename_all = "lowercase", tag = "type")
)]
pub enum SettingsBuilder {
	None,
	#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
	Tls(tls::InboundBuilder),
	#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
	Ws(ws::InboundBuilder),
	#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
	H2(h2::InboundBuilder),
}

impl SettingsBuilder {
	#[allow(clippy::unnecessary_wraps)]
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(match self {
			SettingsBuilder::None => Settings::None,
			#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
			SettingsBuilder::Tls(s) => Settings::Tls(s.build()?),
			#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
			SettingsBuilder::Ws(s) => Settings::Ws(s.build()?),
			#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
			SettingsBuilder::H2(s) => Settings::H2(s.build()?),
		})
	}
}

impl Default for SettingsBuilder {
	fn default() -> Self {
		SettingsBuilder::None
	}
}

#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
impl From<tls::InboundBuilder> for SettingsBuilder {
	fn from(s: tls::InboundBuilder) -> Self {
		SettingsBuilder::Tls(s)
	}
}

#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
impl From<ws::InboundBuilder> for SettingsBuilder {
	fn from(s: ws::InboundBuilder) -> Self {
		SettingsBuilder::Ws(s)
	}
}

#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
impl From<h2::InboundBuilder> for SettingsBuilder {
	fn from(s: h2::InboundBuilder) -> Self {
		SettingsBuilder::H2(s)
	}
}
