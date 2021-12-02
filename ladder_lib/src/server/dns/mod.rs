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

// mod connector;
mod destination;

use crate::{
	prelude::*,
	protocol::{outbound::Error as OutboundError, outbound::TcpConnector, BytesStream},
};
use destination::DnsDestination;
use futures::{lock::Mutex as AsyncMutex, Future, FutureExt};
use std::{
	io,
	task::{Context, Poll},
};
use thiserror::Error;
use tokio::net::UdpSocket;
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_server::{
	authority::{EmptyLookup, LookupObject, MessageResponseBuilder},
	proto::{self, error::ProtoError},
	server::Request,
};

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
		log::debug!(
			"Proxying DNS queries from {} to {}",
			self.bind_addr,
			self.server_addr
		);
		let server_addr = self.server_addr.clone();

		let (client, client_background_task, server_addr) = match server_addr {
			DnsDestination::Udp(addr) => self.connect_udp(ctx, addr).await,
			DnsDestination::Tcp(addr) => self.connect_tcp(ctx, addr).await,
			// DnsDestination::Https(addr) => self.connect_https(ctx, addr).await,
		}?;

		let client = Arc::new(AsyncMutex::new(client));
		// let cache = Arc::new(AsyncMutex::new(LruCache::new(MAX_CACHE_NUM)));

		let sock = UdpSocket::bind(self.bind_addr).await?;
		let mut server_future = trust_dns_server::ServerFuture::new(ProxyRequestHandler {
			client,
			// cache,
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
			client_background_task.await?;
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
			"Running DNS server on {}, proxy all requests to DNS server '{}' through TCP",
			self.bind_addr, server_addr
		);

		let (client, bg_task) = {
			let stream =
				create_transport_stream_timedout(server_addr, &ctx, self.tag.as_ref(), None)
					.await?;
			connect_async_client_over_stream(stream, server_addr).await?
		};

		Ok((client, bg_task, server_addr))
	}
}

async fn create_transport_stream_timedout(
	addr: SocketAddr,
	ctx: &super::Server,
	outbound_tag: Option<&Tag>,
	tls_name: Option<&str>,
) -> Result<BytesStream, BoxStdErr> {
	let outbound = outbound_tag
		.map(|tag| {
			ctx.get_outbound(tag)
				.ok_or_else(|| DnsError::UnknownTag(tag.clone()))
		})
		.transpose()?;

	if let Some(tag) = outbound_tag {
		debug!(
			"Connecting to DNS server '{}' with outbound '{}'",
			addr, tag
		);
	} else {
		debug!("Connecting to DNS server '{}'", addr);
	}

	let timeout_duration = ctx.outbound_handshake_timeout;
	let task = async move {
		// Raw TCP or outbound stream
		let stream = if let Some(outbound) = outbound {
			outbound.settings.connect(&addr.into(), ctx).await?
		} else {
			tokio::net::TcpStream::connect(addr)
				.await
				.map(BytesStream::from)?
		};
		// TLS
		let stream = if let Some(name) = tls_name {
			let connector = crate::utils::tls::Connector::new(vec![], "")?;
			let dest = crate::protocol::socks_addr::SocksDestination::from_str(name)?;
			BytesStream::from(
				connector
					.connect(stream, &SocksAddr::new(dest, addr.port()))
					.await?,
			)
		} else {
			stream
		};
		Ok::<_, BoxStdErr>(stream)
	};
	tokio::time::timeout(timeout_duration, task)
		.map(|res| {
			res.map_err(|_| {
				io::Error::new(
					io::ErrorKind::TimedOut,
					"timeout when trying to establish connection to DNS server",
				)
			})?
		})
		.await
}

async fn connect_async_client_over_stream<S>(
	stream: S,
	server_addr: SocketAddr,
) -> Result<(AsyncClient, BoxBackgroundFut), BoxStdErr>
where
	S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	let (tcp_stream, stream_handle) =
		proto::tcp::TcpStream::from_stream(TokioToFutureAdapter::new(stream), server_addr);

	// Make TcpClientStream and DnsStreamHandle with tcp_stream
	let tcp_client_stream = proto::tcp::TcpClientStream::from_stream(tcp_stream);
	let dns_stream_handle = proto::xfer::BufDnsStreamHandle::new(server_addr, stream_handle);

	// Build multiplexer
	let multiplexer = proto::xfer::DnsMultiplexer::new(
		Box::pin(async move { Ok(tcp_client_stream) }),
		Box::new(dns_stream_handle),
		proto::op::message::NoopMessageFinalizer::new(),
	);

	let (client, bg) = AsyncClient::connect(multiplexer).await?;
	Ok((client, Box::pin(bg) as BoxBackgroundFut))
}

#[derive(Error, Debug)]
enum DnsError {
	#[error("unknown tag '{0}'")]
	UnknownTag(Tag),
	#[error("io error '{0}'")]
	Io(#[from] io::Error),
	#[error("outbound error ({0})")]
	Outbound(#[from] OutboundError),
}

struct ProxyRequestHandler {
	client: Arc<AsyncMutex<AsyncClient>>,
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
			return Box::pin(futures::future::ready(()));
		}

		let op_code = request.message.op_code();
		if op_code != proto::op::OpCode::Query {
			error!(
				"DNS message from {} has op code of '{:?}', must be Query",
				request.src, op_code
			);
			// Returns nothing for wrong op code
			return Box::pin(futures::future::ready(()));
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
			return Box::pin(futures::future::ready(()));
		};

		let name = proto::rr::Name::from(query_name);

		let client = self.client.clone();
		// let cache = self.cache.clone();
		let server_addr = self.server_addr;
		Box::pin(async move {
			let mut response_handle = response_handle;

			// Make a query
			let response = {
				let mut client = client.lock().await;
				debug!(
					"Sending DNS query for domain '{}' to '{}'",
					name, server_addr
				);
				let query_result = client
					.query(
						name.clone(),
						proto::rr::DNSClass::IN,
						proto::rr::RecordType::A,
					)
					.await;

				if let Err(e) = &query_result {
					if let trust_dns_client::error::ClientErrorKind::Io(_e) = e.kind() {
						todo!()
					}
				}

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
				response
			};

			send_response(
				&request,
				&mut response_handle,
				response.answers(),
				response.name_servers(),
				response.additionals(),
			);
		})
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

struct TokioToFutureAdapter<T> {
	inner: T,
	read_buf_filled: usize,
}

impl<T> TokioToFutureAdapter<T> {
	fn new(inner: T) -> Self {
		Self {
			inner,
			read_buf_filled: 0,
		}
	}
}

impl<T: AsyncRead + Unpin> futures::io::AsyncRead for TokioToFutureAdapter<T> {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<io::Result<usize>> {
		let me = self.get_mut();
		// Create ReadBuf
		let mut read_buf = tokio::io::ReadBuf::new(buf);
		read_buf.set_filled(me.read_buf_filled);
		// Poll
		let poll_result = Pin::new(&mut me.inner).poll_read(cx, &mut read_buf);
		match poll_result {
			Poll::Ready(result) => {
				// Clear read_buf_filled
				me.read_buf_filled = 0;
				Poll::Ready(result.map(|_| read_buf.filled().len()))
			}
			Poll::Pending => {
				// Store filled().len() into read_buf_filled for next poll
				me.read_buf_filled = read_buf.filled().len();
				Poll::Pending
			}
		}
	}
}

impl<T: AsyncWrite + Unpin> futures::io::AsyncWrite for TokioToFutureAdapter<T> {
	#[inline]
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.inner).poll_write(cx, buf)
	}

	#[inline]
	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_flush(cx)
	}

	#[inline]
	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_shutdown(cx)
	}
}

impl<T> proto::tcp::DnsTcpStream for TokioToFutureAdapter<T>
where
	T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
	type Time = proto::TokioTime;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		proxy::freedom,
		server::{self, Server},
		test_utils::init_log,
	};
	use lazy_static::lazy_static;
	use std::{collections::HashMap, iter::FromIterator, time::Duration};
	use trust_dns_client::rr::{DNSClass, RData, RecordType};
	use trust_dns_server::server::RequestHandler;

	const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

	lazy_static! {
		static ref DATA: HashMap<Cow<'static, str>, IpAddr> = {
			HashMap::<Cow<'static, str>, IpAddr>::from_iter(vec![
				("localhost.".into(), [1, 0, 0, 1].into()),
				("alice.".into(), [2, 0, 0, 2].into()),
				("bob.".into(), [3, 0, 0, 3].into()),
				("example.com.".into(), [4, 0, 0, 4].into()),
				("google.com.".into(), [5, 0, 0, 5].into()),
				("alice.bob.".into(), [6, 0, 0, 6].into()),
				("this.example.com.".into(), [7, 1, 1, 7].into()),
			])
		};
	}

	struct TestHandler;

	type RequestFuture = dyn Future<Output = ()> + Send;

	impl RequestHandler for TestHandler {
		type ResponseFuture = Pin<Box<RequestFuture>>;

		fn handle_request<R: trust_dns_server::server::ResponseHandler>(
			&self,
			request: Request,
			mut response_handle: R,
		) -> Self::ResponseFuture {
			let msg_type = request.message.message_type();
			if msg_type != proto::op::MessageType::Query {
				error!(
					"DNS message type of request from {} is not Query, but '{:?}'",
					request.src, msg_type
				);
				// Returns nothing for wrong message type
				return Box::pin(futures::future::ready(()));
			}

			let op_code = request.message.op_code();
			if op_code != proto::op::OpCode::Query {
				error!(
					"DNS message from {} has op code of '{:?}', must be Query",
					request.src, op_code
				);
				// Returns nothing for wrong op code
				return Box::pin(futures::future::ready(()));
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
				return Box::pin(futures::future::ready(()));
			};

			let name = proto::rr::Name::from(query_name);

			let ip = {
				let name = query_name.to_string();
				if let Some(ip) = DATA.get(name.as_str()) {
					*ip
				} else {
					panic!("Cannot find IP of '{}'", name);
				}
			};

			log::info!("Querying domain name '{}'", name);
			Box::pin(async move {
				let mrb = MessageResponseBuilder::new(Some(request.message.raw_queries()));
				let mut header = proto::op::Header::new();
				header.set_id(request.message.id());
				header.set_message_type(proto::op::MessageType::Response);
				header.set_op_code(request.message.op_code());
				let mut record = proto::rr::Record::default();
				record.set_name(name);
				match ip {
					IpAddr::V4(ip) => record.set_rdata(proto::rr::RData::A(ip)),
					IpAddr::V6(ip) => record.set_rdata(proto::rr::RData::AAAA(ip)),
				};
				let records = [record];
				let answers_iter: Box<dyn Iterator<Item = &proto::rr::Record> + Send> =
					Box::new(records.iter());
				let response = mrb.build(
					header,
					answers_iter,
					EmptyLookup.iter(),
					EmptyLookup.iter(),
					EmptyLookup.iter(),
				);
				if let Err(e) = response_handle.send_response(response) {
					error!("Cannot send DNS response ({})", e);
				}
			})
		}
	}

	async fn run_test_on_server_future<F, T>(
		server_future: trust_dns_server::ServerFuture<T>,
		mut client: AsyncClient,
		client_background_task: F,
	) where
		F: Future<Output = Result<(), ProtoError>>,
		T: RequestHandler,
	{
		let client_test_task = async move {
			for (domain, &ip) in DATA.iter() {
				let name = proto::rr::Name::from_str(&domain).unwrap();
				let response = client
					.query(name.clone(), DNSClass::IN, RecordType::A)
					.await
					.unwrap();
				let record = &response.answers()[0];
				assert_eq!(record.name(), &name);
				assert_eq!(
					record.rdata(),
					&match ip {
						IpAddr::V4(ip) => RData::A(ip),
						IpAddr::V6(ip) => RData::AAAA(ip),
					}
				)
			}
		}
		.fuse();

		let server_task = async move { server_future.block_until_done().await.unwrap() }.fuse();

		let client_background_task = client_background_task.fuse();

		futures::pin_mut!(server_task);
		futures::pin_mut!(client_test_task);
		futures::pin_mut!(client_background_task);

		futures::select! {
			_ = server_task => (),
			_ = client_test_task => (),
			_ = client_background_task => (),
		};
	}

	async fn run_test_on_udp(server_socket: tokio::net::UdpSocket, test_addr: SocketAddr) {
		debug!("Running test over UDP");
		// Client
		let (client, client_background_task) = {
			let stream = proto::udp::UdpClientStream::<tokio::net::UdpSocket>::new(test_addr);
			AsyncClient::connect(stream).await.unwrap()
		};
		// Server
		let mut server_future = trust_dns_server::ServerFuture::new(TestHandler);
		server_future.register_socket(server_socket);
		// Run test
		run_test_on_server_future(server_future, client, client_background_task).await
	}

	async fn run_test_on_tcp(listener: tokio::net::TcpListener, test_addr: SocketAddr) {
		debug!("Running test over TCP");
		let mut server_future = trust_dns_server::ServerFuture::new(TestHandler);
		server_future.register_listener(listener, Duration::from_secs(1));

		let (client, client_background_task) = {
			let stream = tokio::net::TcpStream::connect(test_addr).await.unwrap();
			let (tcp_stream, stream_handle) =
				proto::tcp::TcpStream::from_stream(TokioToFutureAdapter::new(stream), test_addr);

			// Make TcpClientStream and DnsStreamHandle with tcp_stream
			let tcp_client_stream = proto::tcp::TcpClientStream::from_stream(tcp_stream);
			let dns_stream_handle = proto::xfer::BufDnsStreamHandle::new(test_addr, stream_handle);

			// Build multiplexer
			let multiplexer = proto::xfer::DnsMultiplexer::new(
				Box::pin(async move { Ok(tcp_client_stream) }),
				Box::new(dns_stream_handle),
				proto::op::message::NoopMessageFinalizer::new(),
			);
			AsyncClient::connect(multiplexer).await.unwrap()
		};
		run_test_on_server_future(server_future, client, client_background_task).await
	}

	async fn bind_udp_socket() -> (tokio::net::UdpSocket, SocketAddr) {
		let server_socket = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST.into(), 0))
			.await
			.unwrap();
		let server_addr = server_socket.local_addr().unwrap();
		(server_socket, server_addr)
	}

	#[test]
	fn test_dns() {
		init_log();
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			let (server_socket, server_addr) = bind_udp_socket().await;
			run_test_on_udp(server_socket, server_addr).await
		});
	}

	#[test]
	fn test_dns_over_udp() {
		const PROXY_PORT: u16 = 44453;
		init_log();
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			// Initialize UdpSocket for test server
			let (server_socket, server_addr) = bind_udp_socket().await;
			// Setup config and DNS
			let proxy_bind_addr = SocketAddr::from((LOCALHOST, PROXY_PORT));
			let ctx = {
				let dns_config = Config {
					bind_addr: proxy_bind_addr,
					server_addr: DnsDestination::Udp(server_addr),
					tag: None,
				};
				let mut server = Server::default();
				server.dns = Some(dns_config);
				Arc::new(server)
			};
			let proxy_task = async move {
				debug!("Running proxy task");
				ctx.dns.as_ref().unwrap().serve(ctx.clone()).await.unwrap();
			}
			.fuse();
			// Setup DNS client for testing
			// Start testing
			let test_task = run_test_on_udp(server_socket, proxy_bind_addr).fuse();
			futures::pin_mut!(proxy_task);
			futures::pin_mut!(test_task);
			futures::select! {
				_ = proxy_task => (),
				_ = test_task => (),
			}
		});
	}

	#[test]
	fn test_dns_over_tcp() {
		const PROXY_PORT: u16 = 33411;

		init_log();
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			// Initialize UdpSocket for test server
			let (listener, server_addr) = {
				let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST.into(), 0))
					.await
					.unwrap();
				let local_addr = listener.local_addr().unwrap();
				(listener, local_addr)
			};
			// Setup config and DNS
			let proxy_addr = SocketAddr::from((LOCALHOST, PROXY_PORT));
			let ctx = {
				let dns_config = Config {
					bind_addr: proxy_addr,
					server_addr: DnsDestination::Tcp(server_addr),
					tag: None,
				};
				let mut server = Server::default();
				server.dns = Some(dns_config);
				Arc::new(server)
			};
			let proxy_task = async move {
				debug!("Running proxy task");
				ctx.dns.as_ref().unwrap().serve(ctx.clone()).await.unwrap();
			}
			.fuse();
			// Start testing
			let test_task = run_test_on_tcp(listener, server_addr).fuse();
			futures::pin_mut!(proxy_task);
			futures::pin_mut!(test_task);
			futures::select! {
				r = proxy_task => r,
				r = test_task => r,
			}
		});
	}

	#[test]
	fn test_dns_over_tcp_through_freedom() {
		const PROXY_PORT: u16 = 33422;
		const OUTBOUND_TAG: &str = "proxy";

		init_log();
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			// Initialize UdpSocket for test server
			let (listener, server_addr) = {
				let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST.into(), 0))
					.await
					.unwrap();
				let local_addr = listener.local_addr().unwrap();
				(listener, local_addr)
			};
			// Setup config and DNS
			let proxy_addr = SocketAddr::from((LOCALHOST, PROXY_PORT));
			let ctx = {
				let dns_config = Config {
					bind_addr: proxy_addr,
					server_addr: DnsDestination::Tcp(server_addr),
					tag: Some(OUTBOUND_TAG.into()),
				};
				let outbound = server::outbound::Outbound {
					tag: OUTBOUND_TAG.into(),
					settings: server::outbound::Details::Freedom(freedom::Settings {}.into()),
				};
				let mut server = Server::new(vec![], vec![outbound]).unwrap();
				server.dns = Some(dns_config);
				Arc::new(server)
			};
			let proxy_task = async move {
				debug!("Running proxy task");
				ctx.dns.as_ref().unwrap().serve(ctx.clone()).await.unwrap();
			}
			.fuse();
			// Start testing
			let test_task = run_test_on_tcp(listener, server_addr).fuse();
			futures::pin_mut!(proxy_task);
			futures::pin_mut!(test_task);
			futures::select! {
				r = proxy_task => r,
				r = test_task => r,
			}
		});
	}

	#[cfg(any(feature = "vmess-inbound-openssl", feature = "vmess-inbound-ring"))]
	#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
	#[test]
	fn test_dns_over_tcp_through_vmess() {
		const PROXY_PORT: u16 = 23344;
		const VMESS_PORT: u16 = 44332;
		const OUTBOUND_TAG: &str = "vmess-out";

		use crate::{proxy::vmess, utils::OneOrMany};

		init_log();
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			// Initialize UdpSocket for test server
			let (listener, server_addr) = {
				let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST.into(), 0))
					.await
					.unwrap();
				let local_addr = listener.local_addr().unwrap();
				(listener, local_addr)
			};

			let proxy_addr = SocketAddr::from((LOCALHOST, PROXY_PORT));
			let vmess_addr = SocketAddr::new(LOCALHOST.into(), VMESS_PORT);
			let id = uuid::Uuid::new_v4();
			// Set up VMess task
			let vmess_task = {
				let inbound = {
					let user = vmess::inbound::User::new(id, 0);
					let settings = vmess::inbound::SettingsBuilder {
						users: vec![user],
						..Default::default()
					}
					.build()
					.unwrap();
					server::Inbound {
						tag: "".into(),
						addr: OneOrMany::One([vmess_addr]),
						settings: server::inbound::Details::Vmess(settings),
						err_policy: server::inbound::ErrorHandlingPolicy::Drop,
					}
				};
				let outbound = server::Outbound {
					tag: "".into(),
					settings: server::outbound::Details::Freedom(freedom::Settings {}.into()),
				};
				let server = Server::new(vec![inbound], vec![outbound]).unwrap();
				async move {
					Arc::new(server).serve(None).await.unwrap();
				}
				.fuse()
			};

			// Set up config and DNS
			let ctx = {
				let dns_config = Config {
					bind_addr: proxy_addr,
					server_addr: DnsDestination::Tcp(server_addr),
					tag: Some(OUTBOUND_TAG.into()),
				};
				let vmess_settings = {
					let mut builder = vmess::outbound::SettingsBuilder::new(vmess_addr.into(), id);
					builder.sec = vmess::SecurityType::Chacha20Poly1305;
					builder.build().unwrap()
				};
				let outbound = server::outbound::Outbound {
					tag: OUTBOUND_TAG.into(),
					settings: server::outbound::Details::Vmess(vmess_settings.into()),
				};
				let mut server = Server::new(vec![], vec![outbound]).unwrap();
				server.dns = Some(dns_config);
				Arc::new(server)
			};
			let proxy_task = async move {
				tokio::time::sleep(Duration::from_millis(200)).await;
				debug!("Running proxy task");
				ctx.dns.as_ref().unwrap().serve(ctx.clone()).await.unwrap();
			}
			.fuse();
			// Start testing
			let test_task = async move {
				// Wait for Vmess inbound to initialize
				tokio::time::sleep(Duration::from_millis(400)).await;
				run_test_on_tcp(listener, server_addr).await;
			}
			.fuse();
			futures::pin_mut!(vmess_task);
			futures::pin_mut!(proxy_task);
			futures::pin_mut!(test_task);
			futures::select! {
				r = vmess_task => r,
				r = proxy_task => r,
				r = test_task => r,
			}
		});
	}
}
