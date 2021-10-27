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

use futures::{channel::mpsc::UnboundedSender, stream::StreamExt, FutureExt};
use std::{io, net::SocketAddr};
use std::{
	sync::{
		atomic::{AtomicU64, Ordering},
		Arc,
	},
	time::{Duration, Instant},
};
use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
	net::{TcpListener, TcpStream},
};

const BLOCK_SIZE: usize = 8 * 1024;
const OK: &[u8] = b"OK";

#[derive(Default, Clone)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
	#[inline]
	pub fn add(&self, val: u64) -> u64 {
		self.0.fetch_add(val, Ordering::Relaxed)
	}

	#[inline]
	pub fn get(&self) -> u64 {
		self.0.load(Ordering::Relaxed)
	}
}

#[derive(Debug)]
pub struct TestArgs {
	pub conn_count: usize,
	pub echo_count: usize,
	pub reverse: bool,
	pub server_addr: SocketAddr,
	pub client_server_addr: SocketAddr,
}

impl TestArgs {
	pub async fn test(&self, counter: Counter) -> Duration {
		let start = Instant::now();
		println!("Listening on {}", self.server_addr);
		let listener = TcpListener::bind(self.server_addr)
			.await
			.map_err(|e| format!("cannot bind on {} ({})", self.server_addr, e))
			.unwrap();

		let (shutdown_sender, mut shutdown_receiver) =
			futures::channel::mpsc::unbounded::<io::Error>();
		let test_task = async move {
			let (client_data, server_data) = if self.reverse {
				(None, Some(counter.clone()))
			} else {
				(Some(counter.clone()), None)
			};
			let client_task = run_client(
				self.client_server_addr,
				self.echo_count,
				client_data,
				self.conn_count,
				shutdown_sender.clone(),
			)
			.fuse();
			let server_task = run_server(
				listener,
				self.echo_count,
				server_data,
				shutdown_sender.clone(),
			)
			.fuse();

			futures::pin_mut!(client_task);
			futures::pin_mut!(server_task);

			let res: io::Result<()> = futures::select! {
				res = client_task => res,
				res = server_task => res,
			};

			res
		}
		.fuse();

		let shutdown_task = async move {
			let err = shutdown_receiver.next().await.expect("no senders left");
			println!("Shutting down because of error: {}", err);
			Err::<(), _>(err)
		}
		.fuse();

		futures::pin_mut!(test_task);
		futures::pin_mut!(shutdown_task);

		let res: io::Result<()> = futures::select! {
			res = test_task => res,
			res = shutdown_task => res,
		};

		res.unwrap();

		start.elapsed()
	}
}

async fn run_client(
	server_addr: SocketAddr,
	echo_count: usize,
	reverse_data: Option<Counter>,
	conn_count: usize,
	shutdown_sender: UnboundedSender<io::Error>,
) -> io::Result<()> {
	let mut handles = Vec::new();
	for ind in 0..conn_count {
		let shutdown_sender = shutdown_sender.clone();
		let reverse_data = reverse_data.clone();
		let conn_task = tokio::spawn(async move {
			// println!("Spawning client connection {}", ind);
			let mut stream = match TcpStream::connect(server_addr).await {
				Ok(stream) => stream,
				Err(e) => {
					shutdown_sender
						.unbounded_send(e)
						.expect("receiver not found");
					return;
				}
			};

			let res = if let Some(counter) = reverse_data {
				client_on(&mut stream, echo_count, ind as u8, counter).await
			} else {
				server_on(&mut stream, echo_count).await
			};
			if let Err(e) = res {
				shutdown_sender
					.unbounded_send(e)
					.expect("receiver not found");
			}
		});

		handles.push(conn_task);
	}

	for handle in handles {
		handle.await.expect("spawned task panicked");
	}

	Ok(())
}

async fn run_server(
	listener: TcpListener,
	echo_count: usize,
	reverse_data: Option<Counter>,
	shutdown_sender: UnboundedSender<io::Error>,
) -> io::Result<()> {
	loop {
		let reverse_counter = reverse_data.clone();
		let shutdown_sender = shutdown_sender.clone();

		let (mut stream, _remote_addr) = listener.accept().await?;

		let conn_task = async move {
			let res = if let Some(counter) = reverse_counter {
				client_on(&mut stream, echo_count, 1, counter).await
			} else {
				server_on(&mut stream, echo_count).await
			};
			if let Err(e) = res {
				shutdown_sender.unbounded_send(e).expect("Receiver is dead");
			}
		};

		tokio::spawn(conn_task);
	}
}

async fn server_on<S>(stream: &mut S, echo_count: usize) -> io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut buf = Vec::<u8>::new();
	buf.resize(BLOCK_SIZE, 0);
	stream.read_exact(&mut buf).await?;

	for _ in 0..echo_count {
		// println!("Sending data ({} bytes) to client.", buf.len());
		stream.write_all(&buf).await?;
	}

	// Wait for 'OK'
	buf.resize(OK.len(), 0);
	// println!("Reading OK from server");
	stream.read_exact(&mut buf).await?;

	if buf == OK {
		Ok(())
	} else {
		let msg = format!("result is '{:?}', not 'OK'", buf);
		Err(io::Error::new(io::ErrorKind::InvalidData, msg))
	}
}

async fn client_on<S>(stream: &mut S, echo_count: usize, val: u8, count: Counter) -> io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let data = vec![val; BLOCK_SIZE];
	// println!("Writing data ({} bytes) to server", data.len());
	stream.write_all(&data).await?;

	let mut buf = vec![0u8; BLOCK_SIZE];
	for _ in 0..echo_count {
		// println!("Reading data from server into buf ({} bytes)", data.len());
		stream.read_exact(&mut buf).await?;
		if buf != data {
			let msg = "buf != data";
			return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
		}
		count.add(buf.len() as u64);
	}

	// println!("Sending OK to server");
	stream.write_all(OK).await
}
