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

use super::{
	BoxBackgroundFut, BytesStream, DnsDestination, DnsError, Server, TokioToFutureAdapter,
};
use crate::{
	prelude::*,
	protocol::{outbound::TcpConnector, ProxyContext},
};
use futures::{FutureExt, TryFutureExt};
use std::io;
use trust_dns_client::{
	client::{AsyncClient, ClientHandle},
	op::DnsResponse,
	rr::{DNSClass, Name, RecordType},
};
use trust_dns_server::proto;

const RETRY_COUNT: usize = 3;

pub(super) struct DnsClient {
	outbound_tag: Option<Tag>,
	ctx: Arc<Server>,
	pub bind_addr: SocketAddr,
	pub server_addr: DnsDestination,
	client: Arc<AsyncMutex<Option<AsyncClient>>>,
}

impl DnsClient {
	pub fn new(
		outbound_tag: Option<Tag>,
		ctx: Arc<Server>,
		bind_addr: SocketAddr,
		server_addr: DnsDestination,
	) -> Self {
		Self {
			outbound_tag,
			ctx,
			bind_addr,
			server_addr,
			client: Arc::new(AsyncMutex::new(None)),
		}
	}

	pub async fn query(
		&self,
		name: Name,
		query_type: RecordType,
	) -> Result<DnsResponse, BoxStdErr> {
		for i in 0..RETRY_COUNT {
			match self.priv_query(&name, query_type).await {
				Ok(response) => return Ok(response),
				Err(e) => {
					error!(
						"Cannot established DNS connection to {} ({}), remaining retries: {}",
						self.server_addr, e, RETRY_COUNT - 1 - i,
					);
				}
			}
		}
		if let Some(outbound_tag) = &self.outbound_tag {
			Err(format!(
				"Cannot establishe DNS connection to '{}' through outbound '{}' after {} attempts.",
				self.server_addr, outbound_tag, RETRY_COUNT
			)
			.into())
		} else {
			Err(format!(
				"Cannot establishe DNS connection to '{}' after {} attempts.",
				self.server_addr, RETRY_COUNT
			)
			.into())
		}
	}

	async fn priv_query(
		&self,
		name: &Name,
		query_type: RecordType,
	) -> Result<DnsResponse, BoxStdErr> {
		let mut client = self.client.lock().await;
		let outbound_tag = self.outbound_tag.as_ref();
		let ctx = self.ctx.clone();

		let client_ref = if let Some(c) = client.as_mut() {
			c
		} else {
			let (c, background_task) = match &self.server_addr {
				DnsDestination::Udp(addr) => connect_udp(self.bind_addr, outbound_tag, *addr).await,
				DnsDestination::Tcp(addr) => {
					connect_tcp(self.bind_addr, outbound_tag, ctx, *addr).await
				}
				#[cfg(any(feature = "dns-over-openssl", feature = "dns-over-rustls"))]
				DnsDestination::Tls(addr) => connect_tls(self.bind_addr, outbound_tag, ctx, addr.clone()).await,
			}?;
			{
				let arc_client = self.client.clone();
				tokio::spawn(async move {
					if let Err(e) = background_task.await {
						debug!("DNS transport stopped because of error {}.", e);
					} else {
						debug!("DNS transport stopped.");
					}
					*arc_client.lock().await = None;
				});
			}
			client.get_or_insert(c)
		};
		client_ref
			.query(name.clone(), DNSClass::IN, query_type)
			.map_err(|e| {
				// Clear `client` if there is any error,
				// so a new client will be created next time.
				*client = None;
				e.into()
			})
			.await
	}
}

async fn connect_udp(
	bind_addr: SocketAddr,
	outbound_tag: Option<&Tag>,
	server_addr: SocketAddr,
) -> Result<(AsyncClient, BoxBackgroundFut), BoxStdErr> {
	info!(
		"Running DNS server on {}, proxy all requests to DNS server '{}' (UDP)",
		bind_addr, server_addr
	);
	let (client, bg) = if let Some(tag) = outbound_tag {
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
	Ok((client, bg))
}

async fn connect_tcp(
	bind_addr: SocketAddr,
	outbound_tag: Option<&Tag>,
	ctx: Arc<Server>,
	server_addr: SocketAddr,
) -> Result<(AsyncClient, BoxBackgroundFut), BoxStdErr> {
	info!(
		"Running DNS server on {}, proxy all requests to DNS server '{}' through TCP",
		bind_addr, server_addr
	);

	let (client, bg_task) = {
		let stream =
			create_transport_stream_timedout(&server_addr.into(), &ctx, outbound_tag).await?;
		connect_async_client_over_stream(stream, server_addr).await?
	};

	Ok((client, bg_task))
}

#[cfg(any(feature = "dns-over-openssl", feature = "dns-over-rustls"))]
async fn connect_tls(
	bind_addr: SocketAddr,
	outbound_tag: Option<&Tag>,
	ctx: Arc<Server>,
	server_addr: SocksAddr,
) -> Result<(AsyncClient, BoxBackgroundFut), BoxStdErr> {
	use crate::utils::tls;
	info!(
		"Running DNS server on {}, proxy all requests to DNS server '{}' through TLS",
		bind_addr, server_addr
	);
	let (client, bg_task) = {
		let stream = create_transport_stream_timedout(&server_addr, &ctx, outbound_tag).await?;
		debug!(
			"DNS transport connected, establishing TLS connection to '{}'",
			server_addr
		);
		let tls_stream = tls::Connector::new(vec![], "")?
			.connect(stream, &server_addr)
			.await?;
		debug!("DNS over TLS connected");
		// Use 0.0.0.0:0 for now.
		connect_async_client_over_stream(tls_stream, SocketAddr::new([0, 0, 0, 0].into(), 0))
			.await?
	};

	Ok((client, bg_task))
}

async fn create_transport_stream_timedout(
	addr: &SocksAddr,
	ctx: &Server,
	outbound_tag: Option<&Tag>,
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
			outbound.settings.connect(addr, ctx).await?
		} else {
			ctx.dial_tcp(addr).await?.into()
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
