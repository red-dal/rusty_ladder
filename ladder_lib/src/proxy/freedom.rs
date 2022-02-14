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
	protocol::{
		outbound::{Error as OutboundError, TcpStreamConnector},
		AsyncReadWrite, BufBytesStream, GetProtocolName, ProxyContext,
	},
};
use async_trait::async_trait;

pub const PROTOCOL_NAME: &str = "freedom";

#[derive(Debug, Default)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Settings {}

impl Settings {
	/// This is a wrapper method for `Ok(Self)`.
	///
	/// # Errors
	///
	/// No error will be returned.
	pub fn build<E>(self) -> Result<Self, E> {
		Ok(self)
	}

	#[must_use]
	#[inline]
	#[allow(clippy::unused_self)]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn TcpStreamConnector> {
		None
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// freedom://
	/// ```
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Settings, BoxStdErr> {
		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;
		if url.host().is_some() {
			return Err("URL must have an empty host".into());
		}
		if !url.path().is_empty() && url.path() != "/" {
			return Err("URL must have an empty path".into());
		}
		Ok(Self {})
	}
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpStreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		_dst: &'a SocksAddr,
		_context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		Ok(stream.into())
	}

	#[inline]
	fn addr(&self, _context: &dyn ProxyContext) -> Result<Option<SocksAddr>, OutboundError> {
		Ok(None)
	}
}

#[cfg(feature = "use-udp")]
mod udp_impl {
	use super::Settings;
	use crate::protocol::{
		outbound::{
			udp::{socket, ConnectSocket, Connector, GetConnector, SocketOrTunnelStream},
			Error as OutboundError,
		},
		ProxyContext,
	};
	use async_trait::async_trait;
	use std::net::SocketAddr;

	impl GetConnector for Settings {
		fn get_udp_connector(&self) -> Option<Connector<'_>> {
			Some(Connector::Socket(Box::new(InnerConnector {})))
		}
	}

	struct InnerConnector {}

	#[async_trait]
	impl ConnectSocket for InnerConnector {
		async fn connect_socket(
			&self,
			_context: &dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			let read_half =
				socket::UdpSocketWrapper::bind(SocketAddr::new([0, 0, 0, 0].into(), 0)).await?;
			let write_half = read_half.clone();
			Ok(SocketOrTunnelStream::Socket(socket::DatagramStream {
				read_half: Box::new(read_half),
				write_half: Box::new(write_half),
			}))
		}

		async fn connect_socket_stream<'a>(
			&'a self,
			_stream: socket::DatagramStream,
			_context: &'a dyn ProxyContext,
		) -> Result<SocketOrTunnelStream, OutboundError> {
			Err(OutboundError::CannotConnectOverStream)
		}
	}
}
