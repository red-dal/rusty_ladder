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
			AcceptError, Handshake, Finish, HandshakeError, SessionInfo, StreamAcceptor,
		},
		outbound::Error as OutboundError,
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
		let id = format!("[{:x}]", args.conn_id);
		// ------ handshake ------
		let src = args.addr.get_peer();
		info!(
			"{id} making {proto} inbound handshake with '{src}'.",
			proto = args.inbound.protocol_name(),
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
			let accept_res = match inbound.accept_stream(args.stream, info).await {
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
				Handshake::Stream(handshake_handler, dst) => {
					StreamSession {
						server: &server,
						inbound: &inbound,
						inbound_ind,
						id,
						stat_handle: args.sh,
						src: &src,
						handshake_handler,
						dst: &dst,
					}
					.run()
					.await
				}
				#[cfg(feature = "use-udp")]
				Handshake::Datagram(inbound_stream) => {
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

struct StreamSession<'a> {
	server: &'a Server,
	inbound: &'a Inbound,
	inbound_ind: usize,
	id: String,
	stat_handle: Option<SessionHandle>,
	src: &'a SocketAddr,
	handshake_handler: Box<dyn Finish + 'a>,
	dst: &'a SocksAddr,
}

impl<'a> StreamSession<'a> {
	async fn run(self) -> Result<(), Error> {
		let dst = self.dst;
		let id = self.id;
		let handshake_handler = self.handshake_handler;
		let (outbound, outbound_ind) = if let Some(ind) =
			self.server
				.router
				.choose_outbound(self.inbound_ind, self.src, dst)
		{
			(&self.server.outbounds[ind], ind)
		} else {
			warn!("{id} connecting to '{dst}' is not allowed, replying to inbound...");
			let err = OutboundError::NotAllowed;
			handshake_handler.finish_err(&err).await?;
			return Err(err.into());
		};

		let route = new_route_name(self.src, dst, self.inbound, outbound);
		info!(
			"{id} route: {route}, now connecting to {out_proto} outbound '{out_tag}'...",
			out_proto = outbound.protocol_name(),
			out_tag = outbound.tag
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
				info!("{id} error during outbound connection ({err}), replying to inbound...");
				handshake_handler.finish_err(&err).await?;
				return Err(err.into());
			}
		};
		info!(
			"{id} connected to outbound '{out_tag}', replying to inbound...",
			out_tag = outbound.tag
		);
		let in_stream = handshake_handler.finish().await?;
		info!("{id} inbound handshake finished, relaying...");
		return ProxyStreamHandler {
			id: &id,
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
	id: &'a str,
	stat_handle: &'a Option<SessionHandle>,
	in_ps: BufBytesStream,
	out_ps: BufBytesStream,
	relay_timeout_secs: usize,
}

impl<'a> ProxyStreamHandler<'a> {
	async fn run(self) -> Result<(), Error> {
		let id = self.id;
		let start_time = Instant::now();
		let recv = Counter::new(0);
		let send = Counter::new(0);

		if let Some(stat_handle) = self.stat_handle {
			stat_handle.set_proxying(recv.clone(), send.clone());
		}

		let relay_result = Relay {
			conn_id: id,
			recv: Some(recv.clone()),
			send: Some(send.clone()),
			timeout_secs: self.relay_timeout_secs,
		}
		.relay_stream(self.in_ps.r, self.in_ps.w, self.out_ps.r, self.out_ps.w)
		.await;

		let end_time = Instant::now();

		let recv_count = BytesCount(recv.get());
		let send_count = BytesCount(send.get());
		let lasted_secs = (end_time - start_time).as_secs();
		// print result
		let msg = format!(
			"{id} relay finished with {recv_count} received, {send_count} sent and lasted {lasted_secs} secs",
		);

		if let Err(e) = relay_result {
			match e {
				crate::utils::relay::Error::Io(e) => {
					info!("{msg}, but an error occurred during relay: {e}.");
					return Err(Error::Io(e));
				}
				crate::utils::relay::Error::Inactive(secs) => {
					info!("{msg}, but is closed due to inactivity for {secs} secs.");
					return Err(Error::Inactive(secs));
				}
			}
		}
		info!("{msg}.");

		Ok(())
	}
}

#[inline]
fn new_route_name(
	src: &SocketAddr,
	dst: &SocksAddr,
	inbound: &Inbound,
	outbound: &Outbound,
) -> Cow<'static, str> {
	format!(
		"['{src}', '{in_tag}'|{in_proto}, '{out_tag}'|{out_proto}, '{dst}']",
		in_tag = inbound.tag,
		in_proto = inbound.protocol_name(),
		out_tag = outbound.tag,
		out_proto = outbound.protocol_name(),
	)
	.into()
}
