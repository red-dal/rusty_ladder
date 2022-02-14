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
	inbound::{Callback, CallbackArgs, ErrorHandlingPolicy},
	stat::{Monitor, SessionHandle},
	Error, Inbound, Outbound, Server,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::{
			AcceptError, AcceptResult, FinishHandshake, HandshakeError, SessionInfo, TcpAcceptor,
		},
		outbound::{Error as OutboundError, TcpConnector},
		BufBytesStream, GetProtocolName,
	},
	utils::{
		relay::{Counter, Relay},
		BytesCount,
	},
};
use futures::{future::BoxFuture, FutureExt, TryFutureExt};
use std::future::Future;
use std::time::Instant;
use tokio::time::timeout;

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
			let monitor = monitor.clone();
			// Serving TCP
			let tcp_task = {
				let callback = ServerCallback {
					server: self.clone(),
					#[cfg(feature = "use-udp")]
					udp_session_timeout: self.global.udp_session_timeout,
				};
				inbound
					.serve(inbound_ind, monitor.clone(), callback)
					.map_err(|e| Box::new(e) as BoxStdErr)
			};
			tasks.push(Box::pin(tcp_task));

			// Serving UDP
			#[cfg(feature = "use-udp")]
			{
				use crate::protocol::inbound::udp::DatagramStream;
				struct Callback {
					inbound_ind: usize,
					inbound_tag: Tag,
					monitor: Option<Monitor>,
					server: Arc<Server>,
					udp_session_timeout: std::time::Duration,
				}

				impl super::inbound::UdpCallback for Callback {
					type Fut = BoxFuture<'static, Result<(), Error>>;

					fn run(&self, local_addr: &SocketAddr, stream: DatagramStream) -> Self::Fut {
						let server = self.server.clone();
						let inbound_tag = self.inbound_tag.clone();
						let inbound_ind = self.inbound_ind;
						let local_addr = *local_addr;
						let monitor = self.monitor.clone();
						let udp_session_timeout = self.udp_session_timeout;
						async move {
							udp::dispatch(
								stream,
								inbound_tag,
								inbound_ind,
								local_addr,
								&server,
								monitor,
								udp_session_timeout,
							)
							.await
						}
						.boxed()
					}
				}
				let task = inbound.serve_datagram(Callback {
					monitor,
					inbound_ind,
					inbound_tag: inbound.tag.clone(),
					server: self.clone(),
					udp_session_timeout: self.global.udp_session_timeout,
				});
				tasks.push(task.map_err(|e| Box::new(e) as BoxStdErr).boxed());
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
}

struct ServerCallback {
	server: Arc<Server>,
	#[cfg(feature = "use-udp")]
	udp_session_timeout: std::time::Duration,
}

impl ServerCallback {
	fn priv_run(&self, args: CallbackArgs) -> impl Future<Output = Result<(), Error>> {
		let conn_id_str = format_conn_id(args.conn_id, &args.inbound.tag);
		// ------ handshake ------
		let src = args.addr.get_peer();
		warn!(
			"{} Making {} handshake with incoming connection from {}.",
			conn_id_str,
			args.inbound.protocol_name(),
			src,
		);

		let info = SessionInfo {
			addr: args.addr.clone(),
			is_transport_empty: false,
		};
		let inbound_ind = args.inbound_ind;
		let inbound = args.inbound.clone();
		let server = self.server.clone();
		#[cfg(feature = "use-udp")]
		let udp_session_timeout = self.udp_session_timeout;
		async move {
			let accept_res = match inbound.accept_tcp(args.stream, info).await {
				Ok(res) => res,
				Err(e) => {
					match e {
						AcceptError::Io(e) => return Err(HandshakeError::Io(e).into()),
						AcceptError::ProtocolSilentDrop(stream, e) => {
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
					StreamSession {
						server: &server,
						inbound: &inbound,
						inbound_ind,
						conn_id_str,
						stat_handle: args.sh,
						src: &src,
						handshake_handler,
						dst: &dst,
					}
					.run()
					.await
				}
				#[cfg(feature = "use-udp")]
				AcceptResult::Udp(inbound_stream) => {
					let monitor = args.sh.as_ref().map(|h| h.monitor().clone());
					udp::dispatch(
						inbound_stream,
						inbound.tag.clone(),
						inbound_ind,
						src,
						&server,
						monitor,
						udp_session_timeout,
					)
					.await
				}
			}
		}
	}
}

impl Callback for ServerCallback {
	type Fut = BoxFuture<'static, Result<(), Error>>;

	fn run(&self, args: CallbackArgs) -> Self::Fut {
		self.priv_run(args).boxed()
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

pub struct StreamSession<'a> {
	server: &'a Server,
	inbound: &'a Inbound,
	inbound_ind: usize,
	conn_id_str: String,
	stat_handle: Option<SessionHandle>,
	src: &'a SocketAddr,
	handshake_handler: Box<dyn FinishHandshake + 'a>,
	dst: &'a SocksAddr,
}

impl<'a> StreamSession<'a> {
	async fn run(self) -> Result<(), Error> {
		let dst = self.dst;
		let handshake_handler = self.handshake_handler;
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

		let out_stream = {
			if let Some(sh) = &self.stat_handle {
				sh.set_connecting(outbound_ind, outbound.tag.clone(), self.dst.clone());
			}
			timeout(
				self.server.global.outbound_handshake_timeout,
				outbound.connect(self.dst, self.server),
			)
			.await
			.map_err(|_| OutboundError::new_timeout())?
		};
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
			relay_timeout_secs: self.server.global.relay_timeout_secs,
		}
		.run()
		.await;
	}
}

struct ProxyStreamHandler<'a> {
	conn_id_str: &'a str,
	route_str: &'a str,
	stat_handle: &'a Option<SessionHandle>,
	in_ps: BufBytesStream,
	out_ps: BufBytesStream,
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
		inbound.protocol_name(),
		outbound.tag,
		outbound.protocol_name(),
		dst_addr,
	)
	.into()
}

#[inline]
fn format_conn_id(conn_id: u64, inbound_tag: &str) -> String {
	format!("[{:#06x} {}]", conn_id, inbound_tag)
}
