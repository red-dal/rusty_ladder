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
	protocol::outbound::{TcpConnector, TcpStreamConnector},
};
use std::io;
use thiserror::Error;
use tokio::net::TcpStream;

#[async_trait]
pub trait ProxyContext: Send + Sync {
	async fn lookup_host(&self, domain: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
	async fn dial_tcp(&self, addr: &SocksAddr) -> io::Result<TcpStream>;

	/// Returns a [`Arc<dyn TcpConnector>`].
	///
	/// # Errors
	///
	/// Returns:
	///
	/// - [`GetConnectorError::UnknownTag`] if connector with `tag` cannot be found.
	///
	/// - [`GetConnectorError::NotSupported`] if connector with `tag` is found but does
	///   not support TCP.
	fn get_tcp_connector(&self, tag: &str) -> Result<Arc<dyn TcpConnector>, GetConnectorError>;

	/// Returns a [`Arc<dyn TcpStreamConnector>`].
	///
	/// # Errors
	///
	/// Returns:
	///
	/// - [`GetConnectorError::UnknownTag`] if connector with `tag` cannot be found.
	///
	/// - [`GetConnectorError::NotSupported`] if connector with `tag` is found but does
	///   not support TCP.
	fn get_tcp_stream_connector(
		&self,
		tag: &str,
	) -> Result<Arc<dyn TcpStreamConnector>, GetConnectorError>;
}

#[derive(Debug, Error)]
pub enum GetConnectorError {
	#[error("unknown outbound tag '{0}'")]
	UnknownTag(Tag),
	#[error("{type_name} is not supported on outbound {tag}")]
	NotSupported {
		tag: Tag,
		type_name: Cow<'static, str>,
	},
}
