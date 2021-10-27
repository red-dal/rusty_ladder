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

mod connector;
mod destination;

use super::OUTBOUND_HANDSHAKE_TIMEOUT;
use crate::{
	prelude::*,
	protocol::{OutboundError, TcpConnector},
};
use futures::{lock::Mutex as AsyncMutex, ready, Future};
use lru::LruCache;
use proto::error::ProtoErrorKind;
use std::{
	io,
	task::{Context, Poll},
};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio_rustls::rustls::ClientConfig;
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_https::HttpsClientStreamBuilder;
use trust_dns_server::{
	authority::{EmptyLookup, LookupObject, MessageResponseBuilder},
	proto::{self, error::ProtoError},
	server::Request,
};

use connector::DohTransportStream;
use destination::DnsDestination;

const ALPN_H2: &[u8] = b"h2";

type Fut = dyn Future<Output = Result<(), ProtoError>> + Send;
type BoxBackgroundFut = Pin<Box<Fut>>;

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct Config {
	bind_addr: SocketAddr,
	server_addr: DnsDestination,
	#[cfg_attr(feature = "use_serde", serde(default))]
	tag: Option<Tag>,
}

// TODO:
// - Auto reconnect

impl Config {
	pub(super) async fn serve(&self, ctx: Arc<super::Server>) -> Result<(), BoxStdErr> {
		let server_addr = self.server_addr.clone();

		let (client, bg_task, server_addr) = match server_addr {
			DnsDestination::Udp(addr) => self.connect_udp(ctx, addr).await,
			DnsDestination::Tcp(addr) => self.connect_tcp(ctx, addr).await,
			DnsDestination::Https(addr) => self.connect_https(ctx, addr).await,
		}?;

		let client = Arc::new(AsyncMutex::new(client));
		let cache = Arc::new(AsyncMutex::new(LruCache::new(MAX_CACHE_NUM)));

		let sock = UdpSocket::bind(self.bind_addr).await?;
		let mut server_future = trust_dns_server::ServerFuture::new(ProxyRequestHandler {
			client,
			cache,
			server_addr,
		});
		server_future.register_socket(sock);
		let serve_task = async move {
			server_future
				.block_until_done()
				.await
				.map_err(|e| Box::new(e) as BoxStdErr)
		};
		futures::future::try_join(serve_task, async move {
			bg_task.await?;
			Ok(())
		})
		.await?;

		Ok(())
	}

	async fn connect_udp(
		&self,
		_ctx: Arc<super::Server>,
		server_addr: SocketAddr,
	) -> Result<(AsyncClient, BoxBackgroundFut, SocketAddr), BoxStdErr> {
		info!(
			"Running DNS server on {}, proxy all requests to DNS server '{}' (UDP)",
			self.bind_addr, server_addr
		);
		let (client, bg) = if let Some(tag) = &self.tag {
			let msg = format!(
				"UDP DNS cannot use outbound '{}' as transport currently.",
				tag
			);
			error!("{}", msg);
			return Err(msg.into());
		} else {
			let stream = proto::udp::UdpClientStream::<tokio::net::UdpSocket>::new(server_addr);
			let (client, bg) = AsyncClient::connect(stream).await?;
			(client, Box::pin(bg) as BoxBackgroundFut)
		};
		Ok((client, bg, server_addr))
	}

	async fn connect_tcp(
		&self,
		ctx: Arc<super::Server>,
		server_addr: SocketAddr,
	) -> Result<(AsyncClient, BoxBackgroundFut, SocketAddr), BoxStdErr> {
		info!(
			"Running DNS server on {}, proxy all requests to DNS server '{}' (TCP)",
			self.bind_addr, server_addr
		);

		let (client, bg_task) = if let Some(tag) = &self.tag {
			let outbound = ctx
				.get_outbound(tag)
				.ok_or_else(|| DnsError::UnknownTag(tag.clone()))?;
			// Use outbound
			let outbound_result = tokio::time::timeout(
				OUTBOUND_HANDSHAKE_TIMEOUT,
				outbound.settings.connect(&server_addr.into(), ctx.as_ref()),
			)
			.await
			.map_err(|_| ProtoError::from(ProtoErrorKind::Timeout))?;

			// Make proto::tcp::TcpStream with outbound stream as transport
			let stream = outbound_result
				.map_err(|e| ProtoError::from(ProtoErrorKind::Msg(e.to_string())))?;

			let (tcp_stream, stream_handle) =
				proto::tcp::TcpStream::from_stream(TokioAdapter(stream), server_addr);

			// Make TcpClientStream and DnsStreamHandle with tcp_stream
			let tcp_client_stream = proto::tcp::TcpClientStream::from_stream(tcp_stream);
			let dns_stream_handle =
				proto::xfer::BufDnsStreamHandle::new(server_addr, stream_handle);

			// Build multiplexer
			let multiplexer = proto::xfer::DnsMultiplexer::new(
				Box::pin(async move { Ok(tcp_client_stream) }),
				Box::new(dns_stream_handle),
				proto::op::message::NoopMessageFinalizer::new(),
			);

			let (client, bg) = AsyncClient::connect(multiplexer).await?;
			(client, Box::pin(bg) as BoxBackgroundFut)
		} else {
			// Use tokio::net::TcpStream as transport.
			let (tcp_client_stream, stream_handle) = proto::tcp::TcpClientStream::<
				TokioAdapter<tokio::net::TcpStream>,
			>::new(server_addr);
			// Build multiplexer
			let multiplexer = proto::xfer::DnsMultiplexer::new(
				tcp_client_stream,
				stream_handle,
				proto::op::message::NoopMessageFinalizer::new(),
			);
			let (client, bg) = AsyncClient::connect(multiplexer).await?;
			(client, Box::pin(bg) as BoxBackgroundFut)
		};

		Ok((client, bg_task, server_addr))
	}

	async fn connect_https(
		&self,
		ctx: Arc<super::Server>,
		server_addr: SocksAddr,
	) -> Result<(AsyncClient, BoxBackgroundFut, SocketAddr), BoxStdErr> {
		info!(
			"Running DNS server on {}, proxy all requests to DNS server '{}' (HTTPS)",
			self.bind_addr, server_addr
		);

		let (addr, dns_name) = match server_addr.dest {
			SocksDestination::Name(name) => {
				let addr = tokio::net::lookup_host((name.as_str(), server_addr.port))
					.await?
					.next()
					.ok_or_else(|| format!("Unknown domain '{}'", name))?;
				(addr, name.to_string())
			}
			SocksDestination::Ip(ip) => (SocketAddr::new(ip, server_addr.port), ip.to_string()),
		};

		let mut config = ClientConfig::new();
		config
			.root_store
			.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
		// Need H2 to use DOH
		config.alpn_protocols.push(ALPN_H2.to_vec());
		let builder = HttpsClientStreamBuilder::with_client_config(Arc::new(config));

		let (client, bg_task) = if let Some(tag) = &self.tag {
			let _ = ctx
				.get_outbound(tag)
				.ok_or_else(|| DnsError::UnknownTag(tag.clone()))?;

			// Register context and tag that DOH client should use as transport.
			// This is a hack to force [HttpsClientStreamBuilder] to use custom TCP-like stream.
			// More details on https://github.com/bluejekyll/trust-dns/issues/1100
			DohTransportStream::register(ctx, tag.clone()).await;
			let doh_client_stream = builder.build::<DohTransportStream>(addr, dns_name);
			let (client, bg) = AsyncClient::connect(doh_client_stream).await?;
			(client, Box::pin(bg) as BoxBackgroundFut)
		} else {
			// Use regular [tokio::net::TcpStream] as transport.
			let doh_client_stream =
				builder.build::<TokioAdapter<tokio::net::TcpStream>>(addr, dns_name);
			let (client, bg) = AsyncClient::connect(doh_client_stream).await?;
			(client, Box::pin(bg) as BoxBackgroundFut)
		};

		Ok((client, bg_task, addr))
	}
}

const MAX_CACHE_NUM: usize = 4 * 1024;

#[derive(Error, Debug)]
enum DnsError {
	#[error("unknown tag '{0}'")]
	UnknownTag(Tag),
	#[error("io error '{0}'")]
	Io(#[from] io::Error),
	#[error("outbound error ({0})")]
	Outbound(#[from] OutboundError),
}

type Cache = LruCache<proto::rr::Name, Vec<IpAddr>>;

struct ProxyRequestHandler {
	client: Arc<AsyncMutex<AsyncClient>>,
	cache: Arc<AsyncMutex<Cache>>,
	server_addr: SocketAddr,
}

type RequestFuture = dyn Future<Output = ()> + Send;

impl trust_dns_server::server::RequestHandler for ProxyRequestHandler {
	type ResponseFuture = Pin<Box<RequestFuture>>;

	fn handle_request<R>(&self, request: Request, response_handle: R) -> Self::ResponseFuture
	where
		R: trust_dns_server::server::ResponseHandler,
	{
		trace!(
			"Handling DNS request from {} : {:?}",
			request.src,
			request.message
		);
		let msg_type = request.message.message_type();
		if msg_type != proto::op::MessageType::Query {
			error!(
				"DNS message type of request from {} is not Query, but '{:?}'",
				request.src, msg_type
			);
			// Returns nothing for wrong message type
			return Box::pin(async move {});
		}

		let op_code = request.message.op_code();
		if op_code != proto::op::OpCode::Query {
			error!(
				"DNS message from {} has op code of '{:?}', must be Query",
				request.src, op_code
			);
			// Returns nothing for wrong op code
			return Box::pin(async move {});
		}

		let mut query_name = None;
		for query in request.message.queries() {
			debug!("DNS from {} query domain '{}'", request.src, query.name());
			query_name = Some(query.name());
		}

		let query_name = if let Some(query_name) = query_name {
			query_name
		} else {
			error!("DNS query from {} does not contain a domain", request.src);
			// Returns nothing for containing no domains
			return Box::pin(async move {});
		};

		let name = proto::rr::Name::from(query_name);

		let client = self.client.clone();
		let cache = self.cache.clone();
		let server_addr = self.server_addr;
		Box::pin(async move {
			let mut response_handle = response_handle;

			// Check cache first
			{
				if let Some(ips) = cache.lock().await.get(&name) {
					let answers = ips
						.iter()
						.map(|ip| {
							let rdata = match *ip {
								IpAddr::V4(ip) => proto::rr::RData::A(ip),
								IpAddr::V6(ip) => proto::rr::RData::AAAA(ip),
							};
							proto::rr::Record::from_rdata(name.clone(), 0, rdata)
						})
						.collect::<Vec<_>>();
					send_response(&request, &mut response_handle, &answers, &[], &[]);
					return;
				}
			}

			// Make a query
			let mut response = {
				let mut client = client.lock().await;
				trace!(
					"Sending DNS query for domain '{}' to '{}'",
					name,
					server_addr
				);
				let query_result = client
					.query(
						name.clone(),
						proto::rr::DNSClass::IN,
						proto::rr::RecordType::A,
					)
					.await;

				let response = match query_result {
					Ok(response) => response,
					Err(e) => {
						error!(
							"DNS query to {} for request from {} error ({})",
							server_addr, request.src, e
						);
						return;
					}
				};

				send_response(
					&request,
					&mut response_handle,
					response.answers(),
					response.name_servers(),
					response.additionals(),
				);
				response
			};

			// Put it into cache
			if response.contains_answer() {
				let mut cache = cache.lock().await;
				put_in_cache(&mut cache, &name, &mut response);
			}
		})
	}
}

fn put_in_cache(
	cache: &mut Cache,
	name: &trust_dns_client::rr::Name,
	response: &mut trust_dns_client::op::DnsResponse,
) {
	let answers = response.take_answers().into_iter().filter_map(|r| {
		let parts = r.into_parts();
		trace!(
			"parts.name: {}, name: {}, rdata: {:?}",
			parts.name_labels,
			name,
			parts.rdata
		);
		match parts.rdata {
			proto::rr::RData::A(ip) => Some(IpAddr::from(ip)),
			proto::rr::RData::AAAA(ip) => Some(IpAddr::from(ip)),
			_ => None,
		}
	});

	if let Some(ips) = cache.get_mut(name) {
		ips.clear();
		ips.extend(answers);
	} else {
		cache.put(name.clone(), answers.collect());
	}
}

fn send_response<R>(
	request: &Request,
	response_handle: &mut R,
	answers: &[proto::rr::Record],
	name_servers: &[proto::rr::Record],
	additionals: &[proto::rr::Record],
) where
	R: trust_dns_server::server::ResponseHandler,
{
	let mut header = proto::op::Header::new();
	header.set_id(request.message.id());
	header.set_message_type(proto::op::MessageType::Response);
	header.set_op_code(request.message.op_code());
	header.set_recursion_desired(request.message.recursion_desired());

	let answers_iter: Box<dyn Iterator<Item = &proto::rr::Record> + Send> =
		Box::new(answers.iter());
	let name_servers_iter: Box<dyn Iterator<Item = &proto::rr::Record> + Send> =
		Box::new(name_servers.iter());
	let additionals_iter: Box<dyn Iterator<Item = &proto::rr::Record> + Send> =
		Box::new(additionals.iter());

	let msg_builder = MessageResponseBuilder::new(Some(request.message.raw_queries()));
	let response = msg_builder.build(
		header,
		answers_iter,
		name_servers_iter,
		EmptyLookup.iter(),
		additionals_iter,
	);
	if let Err(e) = response_handle.send_response(response) {
		error!("Error when sending response to src {} ({})", request.src, e);
	}
}

struct TokioAdapter<T>(T);

impl<T: AsyncRead + Unpin> futures::io::AsyncRead for TokioAdapter<T> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		let mut read_buf = tokio::io::ReadBuf::new(buf);
		ready!(Pin::new(&mut self.0).poll_read(cx, &mut read_buf))?;
		Ok(read_buf.filled().len()).into()
	}
}

impl<T: AsyncWrite + Unpin> futures::io::AsyncWrite for TokioAdapter<T> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.0).poll_write(cx, buf)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.0).poll_flush(cx)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.0).poll_shutdown(cx)
	}
}

impl<T> proto::tcp::DnsTcpStream for TokioAdapter<T>
where
	T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	type Time = proto::TokioTime;
}

#[async_trait]
impl proto::tcp::Connect for TokioAdapter<tokio::net::TcpStream> {
	async fn connect(addr: SocketAddr) -> io::Result<Self> {
		Ok(Self(tokio::net::TcpStream::connect(addr).await?))
	}
}
