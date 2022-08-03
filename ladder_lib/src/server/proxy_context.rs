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

use super::Server;
use crate::{
	prelude::*,
	protocol::{
		outbound::{Connector, StreamConnector},
		GetConnectorError, GetProtocolName, ProxyContext, SocksAddr, SocksDestination,
	},
};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
	net::lookup_host,
	net::{TcpStream, ToSocketAddrs},
	time::timeout,
};

#[async_trait]
impl ProxyContext for Server {
	async fn lookup_host(&self, domain: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
		let res = lookup_host((domain, port)).await?.collect();
		Ok(res)
	}

	async fn dial_tcp(&self, addr: &SocksAddr) -> io::Result<TcpStream> {
		trace!("Dialing TCP connection to '{}'", addr);
		let dial_res = match &addr.dest {
			SocksDestination::Name(name) => {
				connect_tcp_timeout((name.as_str(), addr.port), self.global.dial_tcp_timeout).await
			}
			SocksDestination::Ip(ip) => {
				connect_tcp_timeout((*ip, addr.port), self.global.dial_tcp_timeout).await
			}
		};

		if let Err(e) = &dial_res {
			debug!(
				"Error occurred when dialing TCP connection to '{}' ({})",
				addr, e
			);
		}
		dial_res
	}

	fn get_tcp_connector(&self, tag: &str) -> Result<&dyn Connector, GetConnectorError> {
		let outbound = self
			.get_outbound(tag)
			.ok_or_else(|| GetConnectorError::UnknownTag(Tag::from(tag)))?;
		Ok(outbound)
	}

	fn get_tcp_stream_connector(
		&self,
		tag: &str,
	) -> Result<&dyn StreamConnector, GetConnectorError> {
		let outbound = self
			.get_outbound(tag)
			.ok_or_else(|| GetConnectorError::UnknownTag(Tag::from(tag)))?;
		outbound
			.get_tcp_stream_connector()
			.ok_or_else(|| GetConnectorError::NotSupported {
				tag: Tag::from(tag),
				type_name: outbound.protocol_name().into(),
			})
	}
}

async fn connect_tcp_timeout(
	addr: impl ToSocketAddrs,
	timeout_duration: Duration,
) -> io::Result<TcpStream> {
	let stream = match timeout(timeout_duration, TcpStream::connect(addr)).await {
		Ok(res) => res?,
		Err(_) => return Err(io::ErrorKind::TimedOut.into()),
	};

	Ok(stream)
}
