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
	inbound::ErrorHandlingPolicy,
	stat::{Monitor, Handle as StatHandle, HandshakeArgs},
	udp, Error, Inbound, Outbound, Server, OUTBOUND_HANDSHAKE_TIMEOUT,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::{AcceptError, AcceptResult, HandshakeError},
		FinishHandshake, GetProtocolName, OutboundError, ProxyStream, TcpAcceptor, TcpConnector,
	},
	utils::{
		relay::{Counter, Relay},
		BytesCount,
	},
};
use rand::{thread_rng, RngCore};
use std::future::Future;
use std::time::{Instant, SystemTime};
use tokio::{
	net::{TcpListener, TcpStream, UdpSocket},
	time::timeout,
};

impl Server {
	pub(super) async fn priv_serve(
		self: Arc<Self>,
		#[allow(unused_mut)] mut monitor: Option<Monitor>,
	) -> Result<(), BoxStdErr> {
		type FutVec<T> = Vec<Pin<Box<T>>>;
		let mut tasks: FutVec<dyn Future<Output = Result<(), BoxStdErr>> + Send> =
			Vec::with_capacity(self.inbounds.len());

		// Serving Web API
		#[cfg(feature = "use-webapi")]
		if let super::Api::WebApi { addr, secret } = &self.api {
			use futures::FutureExt;

			#[allow(clippy::option_if_let_else)]
			let mon_ref = if let Some(m) = &mut monitor {
				m
			} else {
				let (mon, mon_task) = Monitor::new();
				let mon_task = mon_task.map(|_| Ok(()));

				// This task must be polled in order to update speed.
				tasks.push(Box::pin(mon_task));

				monitor.get_or_insert(mon)
			};

			tasks.push(Box::pin(super::stat::serve_web_api(
				mon_ref.clone(),
				addr,
				secret.clone(),
			)));
			debug_assert!(monitor.is_some());
		}

		// Serve each inbound
		for (inbound_ind, inbound) in self.inbounds.iter().enumerate() {
			let server = self.clone();
			let monitor = monitor.clone();
			// Serving TCP
			tasks.push(Box::pin(async move {
				if let Err(err) = server.handle_inbound_tcp(inbound_ind, monitor).await {
					error!(
						"Error happened on inbound '{}' on {}: {}",
						inbound.tag, inbound.addr, err
					);
					return Err(err);
				};
				Ok(())
			}));

			// Serving UDP
			if let Some(acceptor) = inbound.settings.get_udp_acceptor() {
				for &bind_addr in inbound.addr.as_slice() {
					warn!("Serving UDP on {} for inbound '{}'", bind_addr, inbound.tag);
					let ctx = self.clone();
					let sock = UdpSocket::bind(&bind_addr).await?;
					tasks.push(Box::pin(async move {
						let stream = acceptor.accept_udp(sock).await?;
						udp::dispatch(stream, inbound_ind, bind_addr, ctx.as_ref()).await?;
						Ok(())
					}));
				}
			}
		}
		// Serving DNS
		#[cfg(feature = "dns")]
		{
			if let Some(dns) = &self.dns {
				let task = dns.serve(self.clone());
				tasks.push(Box::pin(task));
			}
		}

		futures::future::try_join_all(tasks).await?;
		Ok(())
	}

	async fn handle_inbound_tcp(
		self: Arc<Self>,
		inbound_ind: usize,
		monitor: Option<Monitor>,
	) -> Result<(), BoxStdErr> {
		let inbound = &self.inbounds[inbound_ind];
		warn!(
			"Serving TCP on {} for inbound '{}'",
			inbound.addr, inbound.tag
		);

		let addrs = inbound.addr.as_slice();
		let mut tasks = Vec::with_capacity(addrs.len());
		for addr in addrs {
			let listener = TcpListener::bind(addr).await?;
			let server = self.clone();
			let monitor = monitor.clone();
			tasks.push(async move {
				server
					.handle_inbound_listener(inbound_ind, &listener, monitor)
					.await
			});
		}
		futures::future::try_join_all(tasks).await.map(|_err| ())
	}

	async fn handle_inbound_listener(
		self: Arc<Self>,
		inbound_ind: usize,
		listener: &TcpListener,
		monitor: Option<Monitor>,
	) -> Result<(), BoxStdErr> {
		loop {
			let (tcp_stream, src_addr) = listener.accept().await?;
			let mut monitor = monitor.clone();
			// randomly generated connection ID
			let conn_id = thread_rng().next_u64();
			let server = self.clone();
			tokio::spawn(async move {
				let stat_handle = if let Some(monitor) = &mut monitor {
					let handle = monitor.register_connection(
						HandshakeArgs {
							conn_id,
							inbound_ind,
							inbound_tag: server.inbounds[inbound_ind].tag.clone(),
							start_time: SystemTime::now(),
							from: src_addr,
						},
					)
					.await;
					Some(handle)
				} else {
					None
				};

				{
					let session = TcpSession::new(
						&server,
						inbound_ind,
						conn_id,
						stat_handle.clone(),
						&src_addr,
					);
					if let Err(e) = session.handle(tcp_stream, src_addr).await {
						error!("Error occurred when serving inbound: {} ", e);
					}
				}

				// kill connection in the monitor
				let end_time = SystemTime::now();
				if let Some(stat_handle) = stat_handle {
					stat_handle.set_dead(end_time).await;
				}
			});
		}
	}

	async fn try_new_outbound_tcp<'a>(
		&self,
		outbound: &Outbound,
		outbound_ind: usize,
		dst_addr: &SocksAddr,
		stat_handle: &Option<StatHandle>,
	) -> Result<ProxyStream, OutboundError> {
		if let Some(stat_handle) = stat_handle {
			stat_handle
				.set_connecting(outbound_ind, outbound.tag.clone(), dst_addr.clone())
				.await;
		}
		timeout(
			OUTBOUND_HANDSHAKE_TIMEOUT,
			outbound.settings.connect(dst_addr, self),
		)
		.await
		.map_err(|_| OutboundError::new_timeout())?
	}
}

fn read_forever<IO>(mut stream: IO)
where
	IO: AsyncRead + Send + Unpin + 'static,
{
	tokio::spawn(async move {
		let mut buf = vec![0_u8; 1024];
		loop {
			let n = match stream.read(&mut buf).await {
				Ok(n) => n,
				Err(_) => {
					// who cares
					return;
				}
			};
			if n == 0 {
				// done reading
				return;
			}
		}
	});
}

pub struct TcpSession<'a> {
	server: Arc<Server>,
	inbound: &'a Inbound,
	inbound_ind: usize,
	conn_id_str: String,
	stat_handle: Option<StatHandle>,
	src: &'a SocketAddr,
}

impl<'a> TcpSession<'a> {
	pub fn new(
		server: &'a Arc<Server>,
		inbound_ind: usize,
		conn_id: u64,
		stat_handle: Option<StatHandle>,
		src: &'a SocketAddr,
	) -> Self {
		let inbound = &server.inbounds[inbound_ind];
		Self {
			server: server.clone(),
			inbound,
			inbound_ind,
			conn_id_str: format!("{:#06x} ({})", conn_id, inbound.tag),
			stat_handle,
			src,
		}
	}

	async fn handle(mut self, tcp_stream: TcpStream, src_addr: SocketAddr) -> Result<(), Error> {
		let inbound = self.inbound;

		// ------ handshake ------
		warn!(
			"{} Making {} handshake with incoming connection from {}.",
			self.conn_id_str,
			inbound.protocol_name(),
			self.src,
		);

		let accept_res = match inbound.settings.accept_tcp(tcp_stream.into()).await {
			Ok(res) => res,
			Err(e) => {
				match e {
					AcceptError::Io(e) => return Err(HandshakeError::Io(e).into()),
					AcceptError::Protocol((stream, e)) => {
						match inbound.err_policy {
							ErrorHandlingPolicy::Drop => {
								// do nothing
							}
							ErrorHandlingPolicy::UnlimitedTimeout => {
								// keep reading until the client drops
								read_forever(stream);
							}
						};
						return Err(HandshakeError::Protocol(e).into());
					}
					AcceptError::TcpNotAcceptable => {
						return Err(HandshakeError::TcpNotAcceptable.into())
					}
					AcceptError::UdpNotAcceptable => {
						return Err(HandshakeError::UdpNotAcceptable.into())
					}
				}
			}
		};

		match accept_res {
			AcceptResult::Tcp((handshake_handler, dst)) => {
				return self.handle_tcp_accept(handshake_handler, &dst).await;
			}
			AcceptResult::Udp(inbound_stream) => {
				udp::dispatch(
					inbound_stream,
					self.inbound_ind,
					src_addr,
					self.server.as_ref(),
				)
				.await
			}
		}
	}

	async fn handle_tcp_accept(
		&mut self,
		handshake_handler: Box<dyn FinishHandshake + 'a>,
		dst: &SocksAddr,
	) -> Result<(), Error> {
		debug!("{} Making outbound to '{}'.", self.conn_id_str, dst);
		let (outbound, outbound_ind) = if let Some(ind) =
			self.server
				.router
				.choose_outbound(self.inbound_ind, self.src, dst)
		{
			(&self.server.outbounds[ind], ind)
		} else {
			let err = OutboundError::NotAllowed;
			handshake_handler.finish_err(&err).await?;
			return Err(err.into());
		};

		info!(
			"{} Proxy route: {}.",
			self.conn_id_str,
			new_route_name(self.src, dst, self.inbound, outbound)
		);

		let out_stream = self
			.server
			.try_new_outbound_tcp(outbound, outbound_ind, dst, &self.stat_handle)
			.await;
		let out_stream = match out_stream {
			Ok(out_stream) => out_stream,
			Err(err) => {
				debug!("Error occurred when making outbound connection ({}). Finishing inbound connection.", err);
				handshake_handler.finish_err(&err).await?;
				return Err(err.into());
			}
		};

		trace!("{} Connection to outbound established.", self.conn_id_str);
		let in_stream = handshake_handler.finish().await?;

		trace!("{} Handshake with inbound finished.", self.conn_id_str);

		return proxy_stream(
			&self.conn_id_str,
			dst,
			&self.stat_handle,
			in_stream,
			out_stream,
		)
		.await;
	}
}

async fn proxy_stream<'a>(
	conn_id_str: &'a str,
	dst_addr: &'a SocksAddr,
	stat_handle: &'a Option<StatHandle>,
	in_ps: ProxyStream,
	out_ps: ProxyStream,
) -> Result<(), Error> {
	let start_time = Instant::now();
	let recv = Counter::new(0);
	let send = Counter::new(0);

	if let Some(stat_handle) = stat_handle {
		stat_handle.set_proxying(recv.clone(), send.clone()).await;
	}

	let relay_result = Relay::new(conn_id_str)
		.set_recv(recv.clone())
		.set_send(send.clone())
		.set_buffer_size(super::RELAY_BUFFER_SIZE)
		.relay_stream(in_ps.r, in_ps.w, out_ps.r, out_ps.w)
		.await;

	let end_time = Instant::now();

	let recv_count = recv.get();
	let send_count = send.get();
	// print result
	let msg = format!(
		"{} Proxy to '{}' finished with {} received, {} sent and lasted {} secs.",
		conn_id_str,
		dst_addr,
		BytesCount(recv_count),
		BytesCount(send_count),
		(end_time - start_time).as_secs(),
	);

	if let Err(e) = relay_result {
		error!("{} But an error occurred ({}).", msg, e);
		return Err(e.into());
	}
	warn!("{}", msg);

	Ok(())
}

#[inline]
fn new_route_name(
	src_addr: &SocketAddr,
	dst_addr: &SocksAddr,
	inbound: &Inbound,
	outbound: &Outbound,
) -> Cow<'static, str> {
	format!(
		"'{}'--[{}, {}]--[{}, {}]->'{}'",
		src_addr,
		inbound.tag,
		inbound.settings.protocol_name(),
		outbound.tag,
		outbound.settings.protocol_name(),
		dst_addr,
	)
	.into()
}
