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
		outbound::{Error as OutboundError, TcpStreamConnector},
		AsyncReadWrite, BufBytesStream, GetConnectorError, GetProtocolName, ProxyContext,
	},
};

const PROTOCOL_NAME: &str = "chain";

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Settings {
	pub chain: Vec<Tag>,
}

impl Settings {
	/// This is a wrapper method for `Ok(Self)`.
	///
	/// # Errors
	///
	/// Return an error if `chain` is empty.
	pub fn build(self) -> Result<Self, BoxStdErr> {
		if self.chain.is_empty() {
			return Err("empty chain".into());
		}
		Ok(self)
	}

	#[must_use]
	#[inline]
	#[allow(clippy::unused_self)]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn TcpStreamConnector> {
		None
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
		dst: &'a SocksAddr,
		context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		debug_assert!(!self.chain.is_empty());
		let links: Result<Vec<(&dyn TcpStreamConnector, SocksAddr, &Tag)>, Error> = self
			.chain
			.iter()
			.map(|tag| {
				context
					.get_tcp_stream_connector(tag)
					.map_err(Error::from)
					.and_then(|con| {
						con.addr(context)
							.map_err(|err| Error::Node {
								tag: tag.clone(),
								err,
							})?
							.ok_or_else(|| Error::WrongType {
								tag: tag.clone(),
								proto_name: con.protocol_name().into(),
							})
							.map(|addr| (con, addr, tag))
					})
			})
			.collect();
		let mut links = links?.into_iter().peekable();
		let mut stream = {
			let (con, _addr, tag) = links.next().ok_or(Error::EmptyChain)?;
			let next_addr = links.peek().map_or(dst, |(_, addr, _)| addr);
			con.connect_stream(stream, next_addr, context)
				.await
				.map_err(|err| Error::Node {
					tag: tag.clone(),
					err,
				})?
		};
		while let Some((con, _addr, tag)) = links.next() {
			let next_addr = links.peek().map_or(dst, |(_, addr, _)| addr);
			stream = con
				.connect_stream(Box::new(stream), next_addr, context)
				.await
				.map_err(|err| Error::Node {
					tag: tag.clone(),
					err,
				})?;
		}

		Ok(stream)
	}

	#[inline]
	fn addr(&self, context: &dyn ProxyContext) -> Result<Option<SocksAddr>, OutboundError> {
		let first_tag = self.chain.first().ok_or(Error::EmptyChain)?;
		let first = context
			.get_tcp_stream_connector(first_tag)
			.map_err(Error::from)?;
		let first_addr = first.addr(context)?.ok_or(Error::ConnectOverStream)?;
		Ok(Some(first_addr))
	}
}

#[cfg(feature = "use-udp")]
impl GetConnector for Settings {
	fn get_udp_connector(&self) -> Option<Connector<'_>> {
		None
	}
}

impl crate::protocol::DisplayInfo for Settings {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("chain")
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("chain(")?;
		crate::utils::fmt_iter(f, self.chain.iter().map(Tag::as_str))?;
		f.write_str(")")
	}
}

// -----------------------------------------------
//                      Error
// -----------------------------------------------

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

// -----------------------------------------------
//                    Tests
// -----------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use crate::protocol::DisplayInfo;

	#[test]
	fn test_display_info() {
		let s = Settings {
			chain: vec!["in".into(), "middle".into(), "out".into()],
		};
		assert_eq!(format!("{}", s.brief()), "chain");
		assert_eq!(format!("{}", s.detail()), "chain('in','middle','out')");
	}
}
