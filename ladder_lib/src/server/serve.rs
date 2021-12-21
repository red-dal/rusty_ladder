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
use super::udp;
use super::{
	inbound::ErrorHandlingPolicy,
	stat::{Monitor, RegisterArgs, SessionHandle},
	Error, Inbound, Outbound, Server,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::{
			AcceptError, AcceptResult, FinishHandshake, HandshakeError, StreamInfo, TcpAcceptor,
		},
		outbound::{Error as OutboundError, TcpConnector},
		BytesStream, GetProtocolName,
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
	net::{TcpListener, TcpStream},
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
			let tcp_task = {
				let monitor = monitor.clone();
				async move {
					if let Err(err) = server
						.handle_inbound_tcp(inbound_ind, monitor.clone())
						.await
					{
						error!(
							"Error happened on inbound '{}' on {}: {}",
							inbound.tag, inbound.addr, err
						);
						return Err(err);
					};
					Ok(())
				}
			};
			tasks.push(Box::pin(tcp_task));

			// Serving UDP
			#[cfg(feature = "use-udp")]
			if let Some(acceptor) = inbound.settings.get_udp_acceptor() {
				let session_timeout = self.udp_session_timeout;
				for &bind_addr in inbound.addr.as_slice() {
					warn!("Serving UDP on {} for inbound '{}'", bind_addr, inbound.tag);
					let ctx = self.clone();
					let sock = tokio::net::UdpSocket::bind(&bind_addr).await?;
					let monitor = monitor.clone();
					tasks.push(Box::pin(async move {
						let stream = acceptor.accept_udp(sock).await?;
						udp::dispatch(
							stream,
							inbound,
							inbound_ind,
							bind_addr,
							ctx.as_ref(),
							monitor,
							session_timeout,
						)
						.await?;
						Ok(())
					}));
				}
			}
		}
		// Serving DNS
		#[cfg(feature = "local-dns")]
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
		info!(
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
			let monitor = monitor.clone();
			// randomly generated connection ID
			let conn_id = thread_rng().next_u64();
			let server = self.clone();
			#[cfg(feature = "use-udp")]
			let udp_session_timeout = self.udp_session_timeout;
			tokio::spawn(async move {
				let stat_handle = monitor.as_ref().map(|m| {
					m.register_tcp_session(RegisterArgs {
						conn_id,
						inbound_ind,
						inbound_tag: server.inbounds[inbound_ind].tag.clone(),
						start_time: SystemTime::now(),
						from: src_addr,
					})
				});

				{
					let inbound = &server.inbounds[inbound_ind];
					let session = InboundConnection {
						server: &server,
						inbound_ind,
						inbound: &server.inbounds[inbound_ind],
						conn_id_str: format_conn_id(conn_id, &inbound.tag),
						stat_handle: stat_handle.clone(),
						src: &src_addr,
						#[cfg(feature = "use-udp")]
						udp_session_timeout,
					};
					if let Err(e) = session.handle(tcp_stream).await {
						error!("Error occurred when serving inbound: {} ", e);
					}
				}

				// kill connection in the monitor
				let end_time = SystemTime::now();
				if let Some(stat_handle) = stat_handle {
					stat_handle.set_dead(end_time);
				}
			});
		}
	}

	async fn try_new_outbound_tcp<'a>(
		&self,
		outbound: &Outbound,
		outbound_ind: usize,
		dst_addr: &SocksAddr,
		stat_handle: &Option<SessionHandle>,
	) -> Result<BytesStream, OutboundError> {
		if let Some(stat_handle) = stat_handle {
			stat_handle.set_connecting(outbound_ind, outbound.tag.clone(), dst_addr.clone());
		}
		timeout(
			self.outbound_handshake_timeout,
			outbound.settings.connect(dst_addr, self),
		)
		.await
		.map_err(|_| OutboundError::new_timeout())?
	}
}

fn silent_drop<IO>(mut stream: IO)
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

pub struct InboundConnection<'a> {
	server: &'a Server,
	inbound: &'a Inbound,
	inbound_ind: usize,
	conn_id_str: String,
	stat_handle: Option<SessionHandle>,
	src: &'a SocketAddr,
	#[cfg(feature = "use-udp")]
	udp_session_timeout: std::time::Duration,
}

impl<'a> InboundConnection<'a> {
	async fn handle(mut self, tcp_stream: TcpStream) -> Result<(), Error> {
		let inbound = self.inbound;

		// ------ handshake ------
		warn!(
			"{} Making {} handshake with incoming connection from {}.",
			self.conn_id_str,
			inbound.protocol_name(),
			self.src,
		);
		let info = StreamInfo {
			peer_addr: tcp_stream.peer_addr()?,
			local_addr: tcp_stream.local_addr()?,
		};
		let accept_res = match inbound
			.settings
			.accept_tcp(tcp_stream.into(), Some(info))
			.await
		{
			Ok(res) => res,
			Err(e) => {
				match e {
					AcceptError::Io(e) => return Err(HandshakeError::Io(e).into()),
					AcceptError::ProtocolSilentDrop((stream, e)) => {
						match inbound.err_policy {
							ErrorHandlingPolicy::Drop => {
								// do nothing
							}
							ErrorHandlingPolicy::UnlimitedTimeout => {
								// keep reading until the client drops
								silent_drop(stream);
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
					AcceptError::Protocol(e) => return Err(HandshakeError::Protocol(e).into()),
				}
			}
		};

		match accept_res {
			AcceptResult::Tcp(handshake_handler, dst) => {
				return self.handle_tcp_accept(handshake_handler, &dst).await;
			}
			#[cfg(feature = "use-udp")]
			AcceptResult::Udp(inbound_stream) => {
				let session_timeout = self.udp_session_timeout;
				let monitor = self.stat_handle.as_ref().map(|h| h.monitor.clone());
				udp::dispatch(
					inbound_stream,
					inbound,
					self.inbound_ind,
					*self.src,
					self.server,
					monitor,
					session_timeout,
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

		let route_str = new_route_name(self.src, dst, self.inbound, outbound);
		info!(
			"{} Proxy route found: {}. Trying to make connection with outbound...",
			self.conn_id_str, route_str
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
		debug!(
			"{} Connection to outbound established. Finishing handshake with inbound...",
			self.conn_id_str
		);
		let in_stream = handshake_handler.finish().await?;
		debug!("{} Handshake with inbound finished. Start relaying traffic between inbound and outbound...", self.conn_id_str);
		return ProxyStreamHandler {
			conn_id_str: &self.conn_id_str,
			route_str: &route_str,
			stat_handle: &self.stat_handle,
			in_ps: in_stream,
			out_ps: out_stream,
			relay_buffer_size: self.server.relay_buffer_size,
			relay_timeout_secs: self.server.relay_timeout_secs,
		}
		.run()
		.await;
	}
}

struct ProxyStreamHandler<'a> {
	conn_id_str: &'a str,
	route_str: &'a str,
	stat_handle: &'a Option<SessionHandle>,
	in_ps: BytesStream,
	out_ps: BytesStream,
	relay_buffer_size: usize,
	relay_timeout_secs: usize,
}

impl<'a> ProxyStreamHandler<'a> {
	async fn run(self) -> Result<(), Error> {
		let start_time = Instant::now();
		let recv = Counter::new(0);
		let send = Counter::new(0);

		if let Some(stat_handle) = self.stat_handle {
			stat_handle.set_proxying(recv.clone(), send.clone());
		}

		let relay_result = Relay {
			conn_id: self.conn_id_str,
			recv: Some(recv.clone()),
			send: Some(send.clone()),
			buffer_size: self.relay_buffer_size,
			timeout_secs: self.relay_timeout_secs,
		}
		.relay_stream(self.in_ps.r, self.in_ps.w, self.out_ps.r, self.out_ps.w)
		.await;

		let end_time = Instant::now();

		let recv_count = recv.get();
		let send_count = send.get();
		// print result
		let msg = format!(
			"{} {} finished with {} received, {} sent and lasted {} secs.",
			self.conn_id_str,
			self.route_str,
			BytesCount(recv_count),
			BytesCount(send_count),
			(end_time - start_time).as_secs(),
		);

		if let Err(e) = relay_result {
			warn!("{} But an error occurred ({}).", msg, e);
			return Err(e.into());
		}
		info!("{}", msg);

		Ok(())
	}
}

#[inline]
fn new_route_name(
	src_addr: &SocketAddr,
	dst_addr: &SocksAddr,
	inbound: &Inbound,
	outbound: &Outbound,
) -> Cow<'static, str> {
	format!(
		"['{}'--{}({})--{}({})--'{}']",
		src_addr,
		inbound.tag,
		inbound.settings.protocol_name(),
		outbound.tag,
		outbound.settings.protocol_name(),
		dst_addr,
	)
	.into()
}

#[inline]
fn format_conn_id(conn_id: u64, inbound_tag: &str) -> String {
	format!("[{:#06x} {}]", conn_id, inbound_tag)
}
