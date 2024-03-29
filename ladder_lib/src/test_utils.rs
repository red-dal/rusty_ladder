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

use crate::{
	prelude::*,
	protocol::{
		inbound::{AcceptError, Handshake, HandshakeError, SessionInfo, StreamAcceptor},
		outbound::{Connector, StreamConnector},
		AsyncReadWrite, BufBytesStream, GetConnectorError, ProxyContext,
	},
	server::stat::Id,
	utils::relay::{Counter, Relay},
};
use async_trait::async_trait;
use futures::FutureExt;
use std::{borrow::Cow, error::Error, io, time::Duration};
use tokio::{
	net::{TcpListener, TcpStream},
	task::{JoinError, JoinHandle},
	time::timeout,
};

const SMALL_CHUNK_NUMS: usize = 8;
const SMALL_CHUNK_SIZE: usize = 128;

const LARGE_CHUNK_NUMS: usize = 3;
const LARGE_CHUNK_SIZE: usize = 8 * 1024;

const TIMEOUT_DUR: Duration = Duration::from_millis(400);

pub fn run_proxy_test<I, Out: StreamConnector>(
	tag: Cow<'static, str>,
	inbound: I,
	out_func: impl Fn(SocksAddr) -> Out,
) where
	I: 'static + StreamAcceptor + Send + Sync,
{
	init_log();

	info!("{} test running", tag);

	let rt = tokio::runtime::Runtime::new().unwrap();
	rt.block_on(async move {
		let (echo_addr, echo_handle) = spawn_echo_server(tag).await;

		let (in_addr, in_handle) = {
			let addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
			let listener = TcpListener::bind(addr).await.unwrap();
			let local_addr = listener.local_addr().unwrap();

			let handle = tokio::spawn(handle_server(listener, inbound));

			(local_addr, handle)
		};

		let outbound = out_func(in_addr.into());

		let out_stream = TcpStream::connect(&in_addr).await.unwrap();
		let mut out_stream = outbound
			.connect_stream(
				Box::new(|_, _| async move { Ok(out_stream.into()) }.boxed()),
				echo_addr.into(),
				&DummyTcpContext(),
			)
			.await
			.unwrap();
		proxy_stream_for_test(&mut out_stream).await;
		unwarp_join_err(echo_handle.await).unwrap();
		unwarp_join_err(in_handle.await).unwrap();
	});
}

async fn proxy_stream_for_test(out_stream: &mut dyn AsyncReadWrite) {
	// small chunks
	let mut buffer = Vec::new();
	let mut result_buffer = Vec::new();

	buffer.resize(SMALL_CHUNK_SIZE, 0);
	result_buffer.resize(buffer.len(), 0);

	for i in 0..SMALL_CHUNK_NUMS {
		let i = i + 1;
		// write random data
		buffer.as_mut_slice().fill(i as u8);
		out_stream.write_all(&buffer).await.unwrap();
		timeout(TIMEOUT_DUR, out_stream.read_exact(&mut result_buffer))
			.await
			.unwrap()
			.unwrap();
		assert_eq!(buffer, result_buffer);
	}

	buffer.resize(LARGE_CHUNK_SIZE, 0);
	result_buffer.resize(buffer.len(), 0);

	for i in 0..LARGE_CHUNK_NUMS {
		// write random data
		buffer.as_mut_slice().fill(i as u8);
		out_stream.write_all(&buffer).await.unwrap();
		timeout(TIMEOUT_DUR, out_stream.read_exact(&mut result_buffer))
			.await
			.unwrap()
			.unwrap();
		assert_eq!(buffer, result_buffer);
	}

	out_stream.shutdown().await.unwrap();
}

async fn spawn_echo_server(tag: Cow<'static, str>) -> (SocketAddr, JoinHandle<io::Result<()>>) {
	let addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
	let listener = TcpListener::bind(addr).await.unwrap();
	let local_addr = listener.local_addr().unwrap();
	let handle = tokio::spawn(async move {
		let (mut stream, _) = listener.accept().await?;
		let mut buffer = [0_u8; 4 * 1024];

		loop {
			let len = stream.read(&mut buffer).await?;
			if len == 0 {
				break;
			}
			info!(
				"{{{}}} Echo server received {} bytes of data, responding...",
				tag, len
			);
			stream.write_all(&buffer[..len]).await?;
		}

		Ok(())
	});
	(local_addr, handle)
}

async fn handle_server<I>(
	listener: TcpListener,
	inbound: I,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
	I: 'static + StreamAcceptor + Send + Sync,
{
	let addr = std::net::Ipv4Addr::LOCALHOST;
	let (stream, _) = listener.accept().await?;
	let accept_result = inbound
		.accept_stream(
			Box::new(stream),
			SessionInfo {
				addr: crate::network::Addrs {
					peer: SocketAddr::new(addr.into(), 11111),
					local: SocketAddr::new(addr.into(), 22222),
				},
				is_transport_empty: true,
			},
		)
		.await;
	let accept_result = match accept_result {
		Ok(h) => h,
		Err(err) => {
			return match err {
				AcceptError::Io(err) => {
					error!("{}", err);
					Err(err.into())
				}
				AcceptError::ProtocolSilentDrop(_, err) => {
					error!("{}", err);
					Err(err)
				}
				AcceptError::TcpNotAcceptable => Err(HandshakeError::TcpNotAcceptable.into()),
				AcceptError::UdpNotAcceptable => Err(HandshakeError::UdpNotAcceptable.into()),
				AcceptError::Protocol(err) => {
					error!("{}", err);
					Err(err.into())
				}
				AcceptError::ProtocolRedirect(_, _, e) => {
					error!("{}", e);
					Err(e)
				}
			}
		}
	};

	match accept_result {
		Handshake::Stream(handshake_handler, dst_addr) => {
			let target_addr = match dst_addr.dest {
				SocksDestination::Name(_) => {
					return Err("Cannot use domain in this test".into());
				}
				SocksDestination::Ip(ip) => SocketAddr::new(ip, dst_addr.port),
			};

			let out_stream = TcpStream::connect(target_addr).await?;
			let in_stream = handshake_handler.finish().await?;

			let out_stream = BufBytesStream::from(out_stream);

			let recv = Counter::new(0);
			let send = Counter::new(0);

			Relay {
				conn_id: Id::new(),
				recv: Some(recv.clone()),
				send: Some(send.clone()),
				timeout_secs: 10,
			}
			.relay_stream(in_stream.r, in_stream.w, out_stream.r, out_stream.w)
			.await?;
		}
		#[cfg(feature = "use-udp")]
		Handshake::Datagram(_) => {
			panic!("Cannot test UDP yet")
		}
	}
	Ok(())
}

struct DummyTcpContext();

#[async_trait]
impl ProxyContext for DummyTcpContext {
	async fn lookup_host(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
		unreachable!()
	}

	async fn dial_tcp(&self, addr: &SocksAddr) -> io::Result<TcpStream> {
		match &addr.dest {
			SocksDestination::Name(name) => TcpStream::connect((name.as_str(), addr.port)).await,
			SocksDestination::Ip(ip) => TcpStream::connect((*ip, addr.port)).await,
		}
	}

	fn get_tcp_connector(&self, _tag: &str) -> Result<&dyn Connector, GetConnectorError> {
		unreachable!()
	}

	fn get_tcp_stream_connector(
		&self,
		_tag: &str,
	) -> Result<&dyn StreamConnector, GetConnectorError> {
		unreachable!()
	}
}

fn unwarp_join_err<T>(res: Result<T, JoinError>) -> T {
	match res {
		Ok(res) => res,
		Err(err) => {
			if err.is_panic() {
				std::panic::resume_unwind(err.into_panic());
			}
			if let Some(err) = err.source() {
				panic!("{}", err);
			} else {
				panic!("{}", err);
			}
		}
	}
}

pub fn init_log() {
	let _ = env_logger::builder().is_test(true).try_init();
}
