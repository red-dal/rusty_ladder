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
	stat::{Id, Monitor, RegisterArgs, SessionHandle},
	Error, Inbound, Outbound, Server,
};
use crate::{
	network,
	prelude::*,
	protocol::{
		inbound::{AcceptError, Finish, Handshake, HandshakeError, SessionInfo, StreamAcceptor},
		outbound::Error as OutboundError,
		AsyncReadWrite, BufBytesStream, GetProtocolName,
	},
	utils::{
		relay::{Counter, Relay},
		BytesCount,
	},
};
use futures::TryFutureExt;
use std::time::Instant;
use std::{future::Future, time::SystemTime};
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
				let server = self.clone();
				#[cfg(feature = "use-udp")]
				let udp_session_timeout = self.global.udp_session_timeout;
				serve_inbound(inbound.clone(), inbound_ind, monitor.clone(), move |args| {
					handle_incoming(
						args,
						server.clone(),
						#[cfg(feature = "use-udp")]
						udp_session_timeout,
					)
				})
				.map_err(|e| Box::new(e) as BoxStdErr)
			};
			tasks.push(Box::pin(tcp_task));

			// Serving UDP
			#[cfg(feature = "use-udp")]
			{
				use crate::protocol::inbound::udp::DatagramStream;
				use futures::future::{BoxFuture, FutureExt};
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

struct CallbackArgs {
	pub sh: Option<SessionHandle>,
	pub stream: Box<dyn AsyncReadWrite>,
	pub addr: network::Addrs,
	pub conn_id: Id,
	pub inbound_ind: usize,
	pub inbound: Arc<Inbound>,
}

/// Accept and handle byte stream request forever.
///
/// # Errors
///
/// Returns an [`Error`] if there are any invalid configurations or IO errors.
///
/// Errors occurred in `callback` will not return.
async fn serve_inbound<F>(
	inbound: Arc<Inbound>,
	inbound_ind: usize,
	monitor: Option<Monitor>,
	callback: impl 'static + Send + Sync + Fn(CallbackArgs) -> F,
) -> Result<(), Error>
where
	F: Future<Output = Result<(), Error>> + Send,
{
	{
		let tag_str = if inbound.tag.is_empty() {
			String::new()
		} else {
			format!(" '{}'", inbound.tag)
		};
		log::warn!(
			"Serving {} inbound{} on {}",
			inbound.protocol_name(),
			tag_str,
			inbound.network
		);
	}
	let callback = Arc::new(callback);
	let mut acceptor = inbound.network.bind().await?;
	loop {
		let callback = callback.clone();
		let ar = acceptor.accept().await?;
		let monitor = monitor.clone();
		// randomly generated connection ID
		let conn_id = rand::thread_rng().next_u64();
		let inbound = inbound.clone();
		tokio::spawn(async move {
			let stream = ar.stream;
			let from = ar.addr.get_peer();
			let stat_handle = monitor.as_ref().map(|m| {
				m.register_tcp_session(RegisterArgs {
					conn_id,
					inbound_ind,
					inbound_tag: inbound.tag.clone(),
					start_time: SystemTime::now(),
					from,
				})
			});
			if let Err(e) = callback(CallbackArgs {
				sh: stat_handle.clone(),
				stream,
				addr: ar.addr,
				conn_id,
				inbound_ind,
				inbound: inbound.clone(),
			})
			.await
			{
				let in_proto = inbound.protocol_name();
				if let Error::Inactive(secs) = &e {
					warn!(
						"[{conn_id:x}] connection closed in \
                            'in_tag'|{in_proto} session due to inactivity for {secs} secs."
					);
				} else {
					error!(
						"[{conn_id:x}] error occurred in \
                            '{in_tag}'|{in_proto} session: {e} ",
						in_tag = inbound.tag,
					);
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

async fn handle_incoming(
	args: CallbackArgs,
	server: Arc<Server>,
	#[cfg(feature = "use-udp")] udp_session_timeout: std::time::Duration,
) -> Result<(), Error> {
	let id = format!("[{:x}]", args.conn_id);
	// ------ handshake ------
	// Source (peer) of the current stream.
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
	let server = server.clone();
	#[cfg(feature = "use-udp")]
	let udp_session_timeout = udp_session_timeout;
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
				AcceptError::ProtocolRedirect(stream, addr, e) => {
					if let ErrorHandlingPolicy::UnlimitedTimeout = inbound.err_policy {
						redirect_and_forget(server.clone(), addr, stream);
					}
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

fn redirect_and_forget(
	context: Arc<dyn crate::protocol::ProxyContext>,
	addr: SocketAddr,
	mut stream: Box<dyn AsyncReadWrite>,
) {
	tokio::spawn(async move {
		let addr = SocksAddr::from(addr);
		let mut out_stream = match context.dial_tcp(&addr).await {
			Ok(stream) => stream,
			Err(e) => {
				warn!("Cannot connect to {addr} during redirect ({e})");
				return;
			}
		};
		if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut out_stream).await {
			warn!("Error during bidirectional copy to {addr} ({e})");
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
