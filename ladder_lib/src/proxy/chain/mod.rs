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

#[cfg(feature = "use-udp")]
use crate::protocol::outbound::udp::{Connector, GetConnector};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpConnector, TcpStreamConnector},
		BufBytesStream, GetConnectorError, GetProtocolName, ProxyContext,
	},
};

const PROTOCOL_NAME: &str = "chain";

type ArcStreamConnector = Arc<dyn TcpStreamConnector>;

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Settings {
	pub chain: Vec<Tag>,
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpConnector for Settings {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		debug_assert!(!self.chain.is_empty());

		let mut tag_iter = self.chain.iter();

		let first = {
			let tag = tag_iter.next().ok_or(Error::EmptyChain)?;
			context.get_tcp_connector(tag).map_err(Error::from)?
		};

		let nodes: Vec<ArcStreamConnector> = {
			let mut nodes: Vec<ArcStreamConnector> = Vec::new();
			for tag in tag_iter {
				let connector = context.get_tcp_stream_connector(tag).map_err(Error::from)?;
				nodes.push(connector);
			}
			nodes
		};

		let mut stream = {
			let first_addr = nodes.first().map_or(dst, |node| node.addr());
			first.connect(first_addr, context).await?
		};

		let mut nodes_iter = nodes.iter().peekable();

		while let Some(node) = nodes_iter.next() {
			let next_addr = nodes_iter.peek().map_or(dst, |node| node.addr());
			stream = node
				.connect_stream(Box::new(stream), next_addr, context)
				.await?;
		}

		Ok(stream)
	}
}

#[cfg(feature = "use-udp")]
impl GetConnector for Settings {
	fn get_udp_connector(&self) -> Option<Connector<'_>> {
		None
	}
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("invalid chain node (tag: '{tag}', protocol: {proto_name})")]
	WrongType {
		tag: Tag,
		proto_name: Cow<'static, str>,
	},
	#[error("unknown chain node tag '{0}'")]
	UnknownTag(Tag),
	#[error("chain IO error on '{tag}'({err})")]
	Node { tag: Tag, err: OutboundError },
	#[error("cannot connect chain proxy over stream")]
	ConnectOverStream,
	#[error("empty chain")]
	EmptyChain,
}

impl From<Error> for OutboundError {
	fn from(e: Error) -> Self {
		OutboundError::Protocol(Box::new(e))
	}
}

impl From<GetConnectorError> for Error {
	fn from(e: GetConnectorError) -> Self {
		match e {
			GetConnectorError::UnknownTag(e) => Error::UnknownTag(e),
			GetConnectorError::NotSupported { tag, type_name } => Error::WrongType {
				tag,
				proto_name: type_name,
			},
		}
	}
}
