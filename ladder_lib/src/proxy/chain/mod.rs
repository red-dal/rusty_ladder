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
		outbound::{Error as OutboundError, StreamFunc, TcpStreamConnector},
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
		stream_func: Box<StreamFunc<'a>>,
		dst: SocksAddr,
		context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		use futures::{future::BoxFuture, FutureExt};

		fn connect_link<'a>(
			dst: SocksAddr,
			context: &'a dyn ProxyContext,
			mut links: Vec<&'a dyn TcpStreamConnector>,
			base_stream_func: Box<StreamFunc<'a>>,
		) -> BoxFuture<'a, Result<Box<dyn AsyncReadWrite>, OutboundError>> {
			let curr_link = links.pop();
			async move {
				if let Some(curr_link) = curr_link {
					let stream = curr_link
						.connect_stream(
							Box::new(|addr: SocksAddr, context: &dyn ProxyContext| {
								// Make base stream with current address.
								async move {
									let stream =
										connect_link(addr, context, links, base_stream_func)
											.await
											.map_err(OutboundError::into_io_err)?;
									Ok(stream)
								}
								.boxed()
							}),
							dst,
							context,
						)
						.await?;
					Ok(Box::new(stream) as Box<dyn AsyncReadWrite>)
				} else {
					base_stream_func(dst.clone(), context)
						.await
						.map_err(OutboundError::Io)
				}
			}
			.boxed()
		}

		debug_assert!(!self.chain.is_empty());
		let mut links: Vec<&dyn TcpStreamConnector> = Vec::new();
		for tag in &self.chain {
			links.push(context.get_tcp_stream_connector(tag).map_err(Error::from)?);
		}
		connect_link(dst.clone(), context, links, stream_func)
			.await
			.map(Into::into)
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
	use crate::protocol::{outbound::TcpConnector, CompositeBytesStream, DisplayInfo};
	use futures::FutureExt;

	#[test]
	fn test_display_info() {
		let s = Settings {
			chain: vec!["in".into(), "middle".into(), "out".into()],
		};
		assert_eq!(format!("{}", s.brief()), "chain");
		assert_eq!(format!("{}", s.detail()), "chain('in','middle','out')");
	}

	#[test]
	fn test_connect_stream() {
		use std::io;
		use tokio::net::TcpStream;

		struct DummyProxy {
			tag: String,
			addr: SocketAddr,
		}

		impl GetProtocolName for DummyProxy {
			fn protocol_name(&self) -> &'static str {
				"dummy"
			}
		}

		#[async_trait]
		impl TcpStreamConnector for DummyProxy {
			async fn connect_stream<'a>(
				&'a self,
				stream_func: Box<StreamFunc<'a>>,
				dst: SocksAddr,
				context: &'a dyn ProxyContext,
			) -> Result<BufBytesStream, OutboundError> {
				let addr = SocksAddr::from(self.addr);
				let mut stream = { stream_func(SocksAddr::from(self.addr), context).await? };
				let tag = &self.tag;
				stream
					.write(format!("[({tag}) connecting to {addr} for {dst}]\n").as_bytes())
					.await?;
				Ok(stream.into())
			}
		}

		struct DummpContext {
			first: DummyProxy,
			second: DummyProxy,
			third: DummyProxy,
		}

		#[async_trait]
		impl ProxyContext for DummpContext {
			async fn lookup_host(&self, _domain: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
				unreachable!()
			}

			async fn dial_tcp(&self, _addr: &SocksAddr) -> io::Result<TcpStream> {
				unreachable!()
			}

			fn get_tcp_connector(&self, _tag: &str) -> Result<&dyn TcpConnector, GetConnectorError> {
				unreachable!()
			}

			fn get_tcp_stream_connector(
				&self,
				tag: &str,
			) -> Result<&dyn TcpStreamConnector, GetConnectorError> {
				Ok(match tag {
					"first" => &self.first,
					"second" => &self.second,
					"third" => &self.third,
					_ => return Err(GetConnectorError::UnknownTag(tag.into())),
				})
			}
		}

		let context = DummpContext {
			first: DummyProxy {
				tag: "first".into(),
				addr: "127.0.0.1:2222".parse().unwrap(),
			},
			second: DummyProxy {
				tag: "second".into(),
				addr: "127.0.0.1:3333".parse().unwrap(),
			},
			third: DummyProxy {
				tag: "third".into(),
				addr: "127.0.0.1:4444".parse().unwrap(),
			},
		};
		let proxy = Settings {
			chain: vec!["first".into(), "second".into(), "third".into()],
		};
		let (server, mut end) = tokio::io::duplex(1024);
		let mut server = {
			let (r, w) = tokio::io::split(server);
			Box::new(CompositeBytesStream::new(r, w)) as Box<dyn AsyncReadWrite>
		};
		let task = async move {
			let mut stream = proxy
				.connect_stream(
					Box::new(|addr: SocksAddr, _| {
						async move {
							server
								.write(format!("[(base) connecting to {addr}]\n").as_bytes())
								.await
								.unwrap();
							Ok(server)
						}
						.boxed()
					}),
					"localhost:9999".parse().unwrap(),
					&context,
				)
				.await
				.unwrap();

			let mut data = Vec::<u8>::with_capacity(8 * 1024);
			end.read_buf(&mut data).await.unwrap();

			{
				let mut data = std::str::from_utf8(&data).unwrap().lines();
				assert_eq!(
					data.next().unwrap(),
					"[(base) connecting to 127.0.0.1:2222]"
				);
				assert_eq!(
					data.next().unwrap(),
					"[(first) connecting to 127.0.0.1:2222 for 127.0.0.1:3333]"
				);
				assert_eq!(
					data.next().unwrap(),
					"[(second) connecting to 127.0.0.1:3333 for 127.0.0.1:4444]"
				);
				assert_eq!(
					data.next().unwrap(),
					"[(third) connecting to 127.0.0.1:4444 for localhost:9999]"
				);
				assert!(data.next().is_none());
			}

			{
				data.clear();
				stream.write_all(b"hello world!").await.unwrap();
				end.read_buf(&mut data).await.unwrap();
				assert_eq!(
					std::str::from_utf8(data.as_slice()).unwrap(),
					"hello world!"
				);

				end.write_all(b"hello back to you!").await.unwrap();
				data.clear();
				stream.read_buf(&mut data).await.unwrap();
				assert_eq!(
					std::str::from_utf8(data.as_slice()).unwrap(),
					"hello back to you!"
				);
			}
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}
}
