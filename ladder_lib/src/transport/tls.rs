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

use crate::{
	prelude::*,
	protocol::{AsyncReadWrite, ProxyContext},
	utils::tls::{Acceptor, Connector},
};
use smol_str::SmolStr;
use std::io;

pub use crate::utils::tls::{ClientStream, ConfigError, ServerStream};

pub struct Outbound {
	pub connector: Connector,
}

impl Outbound {
	#[inline]
	pub async fn connect(
		&self,
		addr: &SocksAddr,
		context: &dyn ProxyContext,
	) -> io::Result<Box<dyn AsyncReadWrite>> {
		self.connect_stream(context.dial_tcp(addr).await?, addr).await.map(Into::into)
	}
	
	#[inline]
	pub async fn connect_stream<IO>(
		&self,
		stream: IO,
		addr: &SocksAddr,
	) -> io::Result<ClientStream<IO>>
	where
		IO: AsyncRead + AsyncWrite + Unpin,
	{
		return self.connector.connect(stream, addr).await;
	}
}

#[derive(Clone, Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct OutboundBuilder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub alpns: Vec<SmolStr>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub ca_file: String,
}

impl OutboundBuilder {
	/// Create a new [`Outbound`]
	///
	/// # Errors
	///
	/// Returns a [`ConfigError`] if there are errors in the configuration.
	pub fn build(self) -> Result<Outbound, ConfigError> {
		debug!(
			"Building TLS outbound with ca_file '{}', alpns '{:?}'",
			self.ca_file, self.alpns
		);
		let connector = Connector::new(self.alpns.iter().map(|s| s.as_bytes()), &self.ca_file)?;
		Ok(Outbound { connector })
	}
}

pub struct Inbound {
	acceptor: Acceptor,
}

impl Inbound {
	#[inline]
	pub async fn accept<IO>(&self, stream: IO) -> io::Result<ServerStream<IO>>
	where
		IO: AsyncRead + AsyncWrite + Unpin,
	{
		self.acceptor.accept(stream).await
	}
}

#[derive(Debug, Clone)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct InboundBuilder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub alpns: Vec<SmolStr>,
	pub cert_file: String,
	pub key_file: String,
}

impl InboundBuilder {
	/// Create a new [`Inbound`].
	///
	/// # Errors
	///
	/// Returns a [`ConfigError`] if there are errors in the configuration.
	pub fn build(self) -> Result<Inbound, ConfigError> {
		debug!(
			"Building TLS inbound with cert_file '{}', key_file '{}', alpns '{:?}'",
			self.cert_file, self.key_file, self.alpns
		);
		let acceptor = Acceptor::new(
			&self.cert_file,
			&self.key_file,
			self.alpns.iter().map(|a| a.as_bytes()),
		)?;
		Ok(Inbound { acceptor })
	}
}
