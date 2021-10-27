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

use super::http_utils;
use crate::{
	prelude::*,
	utils::websocket::{self, Message},
};
use futures::SinkExt;
use rand::thread_rng;
use serde::Serialize;
use std::{collections::HashMap, io, time::Duration};
use tokio::{
	self,
	net::{TcpListener, TcpStream},
};

pub type CommandStream = websocket::MessageStream<TcpStream>;
pub type Stream<RW> = websocket::Stream<RW>;

const COMMAND_STREAM_TIMEOUT: Duration = Duration::from_millis(3000);
const COMMAND_MESSAGE_TIMEOUT: Duration = Duration::from_millis(3000);

const PAYLOAD_TIMEOUT: Duration = Duration::from_millis(3000);
const PAYLOAD_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(3000);

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/**
Builder for [`Settings`].

When `settings.connect` is called to connect to `remote_addr`:

### Transport

1. Wait for websocket connection on `"ws://localhost:{command_port}{command_path}"` from browser
   as command stream (timeout in [`COMMAND_STREAM_TIMEOUT`]). The command stream will be kept alive .
2. Generate a secret and encode it with base64 as `secret`.
3. Open TCP listener on localhost with address `local_payload_addr`.
4. Send `Command { dst: "{scheme}://{remote_addr}{server_path}", src: "ws://{local_payload_addr}/{secret}" }`
   where `scheme` is either `"ws"` or `"wss"` determined by `use_wss` field.
5. Wait for websocket connection on `"ws://{local_payload_addr}/{secret}"` from browser
   and return.

### Browser

1. Create websocket connection to `"ws://localhost:{command_port}{command_path}"`
   if it is not already created.
2. Wait for a [`Command`] in JSON and deserialize it.

And for each `cmd` until there are no more commands:

1. Create websocket connection to `cmd.src` as the payload stream.
2. Create websocket connection to `cmd.dst` as the server stream.
3. Proxy traffic between the payload stream and the server stream.

```not_rust
+----------------------------------------------------------+
|                     Local Machine                        |
|                                                          |
|    +-----------+                     +--------------+    |
|    |           |                     |              |    |
|    |           |                     |              |    |
|    |           | Create websocket to |              |    |
|    |           | `command_port` on   |              |    |
|    |           | localhost and wait  |              |    |
|    |           |  for command.       |              |    |
|    |           |<--------------------+              |    |
|    |           |                     |              |    |
|    |           |                     |              |    |
|    |           |                     |              |    |
|    |           | `Command` in JSON   |              |    |
|    |           +-------------------->|              |    |
|    |           |                     |              |    |
|    |           |                     |              |    |
|    |           |                     |              |    |
|    |           |                     |   Browser    |    |
|    | transport | Create websocket to |              |    |
|    |           |   `cmd.src`         |              |    |     Create websocket  +----------+
|    |           |<--------------------+              |    |       to `cmd.dst`    |          |
|    |           |                     |              |    |     and proxy traffic |  Remote  |
|    |           |                     |              |    |     from `cmd.src`    | WS proxy |
|    |           |                     |              |    |       to `cmd.dst`    |  server  |
|    |           |                     |              +----+---------------------->|          |
|    |           |                     |              |    |                       |          |
|    +-----------+                     +--------------+    |                       +----------+
|                                                          |
|                                                          |
+----------------------------------------------------------+
```
*/
#[derive(Clone, Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct SettingsBuilder {
	/// Path for the remote websocket server.
	/// This must be identical to the path on server's configuration.
	///
	/// Empty by default.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub server_path: String,

	/// True if you need to use wss instead of ws to connect to remote server.
	///
	/// False by default.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub use_wss: bool,

	/// Port for browser to connect to.
	/// Command stream will be accepted on LOCALHOST:command_port.
	pub command_port: u16,

	/// Path for the local command websocket server for browser to connect.
	///
	/// Empty by default.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub command_path: String,
}

impl SettingsBuilder {
	pub fn build(self) -> Settings {
		Settings {
			server_path: self.server_path,
			use_wss: self.use_wss,
			command_port: self.command_port,
			command_path: self.command_path,
			command_stream: Arc::new(AsyncMutex::new(None)),
		}
	}
}

pub struct Settings {
	server_path: String,
	use_wss: bool,
	command_port: u16,
	command_path: String,
	command_stream: Arc<AsyncMutex<Option<CommandStream>>>,
}

impl Clone for Settings {
	fn clone(&self) -> Self {
		// Copy everything except command stream
		Self {
			server_path: self.server_path.clone(),
			use_wss: self.use_wss,
			command_port: self.command_port,
			command_path: self.command_path.clone(),
			command_stream: Arc::new(AsyncMutex::new(None)),
		}
	}
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, Debug))]
/// A command that tells the browser to connect to remote proxy server 'dst' and local payload server 'src',
/// then proxy traffic between this two.
struct Command {
	/// A URL for remote websocket proxy server.
	dst: String,
	/// A URL for local websocket payload server.
	src: String,
}

impl Settings {
	pub async fn connect(&self, addr: &SocksAddr) -> io::Result<Stream<TcpStream>> {
		fn url_to_io_err(e: BoxStdErr) -> io::Error {
			io::Error::new(io::ErrorKind::InvalidInput, e)
		}
		debug!("Preparing browser connection to {}", addr);

		let mut cmd_stream_holder = self.command_stream.lock().await;
		loop {
			if let Some(cmd_stream) = cmd_stream_holder.as_mut() {
				// Listen on a port and prepare for the payload connection.
				let payload_listener = {
					let payload_addr = SocketAddr::from(([127, 0, 0, 1], 0));
					TcpListener::bind(payload_addr).await?
				};
				let payload_addr = payload_listener.local_addr()?;

				// A secret for authenticating browser payload connection.
				// The payload connection will only be accepted if this secret is used.
				let secret_path = {
					let secret: u128 = thread_rng().gen();
					format!(
						"/{}",
						base64::encode_config(&secret.to_be_bytes(), base64::URL_SAFE_NO_PAD)
					)
				};

				// Put secret in the path section of the URL.
				let command = {
					let command = Command {
						// Tells browser to connect to the remote proxy server
						// dst: format!("{}://{}{}", server_scheme, addr, self.server_path),
						dst: http_utils::make_ws_uri(
							self.use_wss,
							&addr.to_string(),
							&self.server_path,
						)
						.map_err(url_to_io_err)?
						.to_string(),
						// Tells browser to connect to the local payload server
						// src: format!("ws://{}{}", payload_addr, secret_path),
						src: http_utils::make_ws_uri(
							false,
							&payload_addr.to_string(),
							&secret_path,
						)
						.map_err(url_to_io_err)?
						.to_string(),
					};
					Message::text(serde_json::to_string(&command)?)
				};

				// Send the command to the browser.
				// If this failed, the command stream holder should be set to None.
				if let Err(err) = cmd_stream.send(command).await {
					error!("Unable to send commands to the browser ({})", err);
					*cmd_stream_holder = None;
					return Err(io::Error::new(io::ErrorKind::Other, err));
				};

				// Waiting for the payload connection from browser
				let (payload_stream, _browser_addr) =
					tokio::time::timeout(PAYLOAD_TIMEOUT, payload_listener.accept()).await??;

				// Only websocket connection with the 'secret' as path will be accepted
				let payload_stream = tokio::time::timeout(
					PAYLOAD_HANDSHAKE_TIMEOUT,
					websocket::accept(payload_stream, &HashMap::new(), &secret_path),
				)
				.await??;

				return Ok(payload_stream);
			}
			// If the command connection with a browser hasn't been established,
			// wait for it.
			let listener = TcpListener::bind(SocketAddr::new(LOCALHOST, self.command_port)).await?;
			let (tcp_stream, _) =
				tokio::time::timeout(COMMAND_STREAM_TIMEOUT, listener.accept()).await??;

			let stream = tokio::time::timeout(
				COMMAND_MESSAGE_TIMEOUT,
				websocket::accept_message_stream(tcp_stream, &HashMap::new(), &self.command_path),
			)
			.await??;

			// Command connection established,
			// loop back.
			*cmd_stream_holder = Some(stream);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{websocket, Command, SettingsBuilder, LOCALHOST};
	use crate::test_utils;
	use async_tungstenite::tungstenite::Message;
	use futures::StreamExt;
	use std::{net::SocketAddr, str::FromStr, time::Duration};
	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		net::{TcpListener, TcpStream},
	};

	#[test]
	fn test_browser_transport_connect() {
		test_utils::init_log();
		// const SERVER_PATH: &str = "remote-server:54321";
		const SERVER_PATH: &str = "/proxy";
		const COMMAND_PORT: u16 = 33321;
		const COMMAND_PATH: &str = "/command";
		const PAYLOAD: &[u8] = &[2_u8; 1024];

		let command_addr = SocketAddr::new(LOCALHOST, COMMAND_PORT);

		let rt = tokio::runtime::Runtime::new().unwrap();

		rt.block_on(async move {
			let server_listener = TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
				.await
				.unwrap();
			let server_addr = server_listener.local_addr().unwrap();

			let browser_task = async move {
				tokio::time::sleep(Duration::from_millis(250)).await;
				log::info!("[Browser] Running browser task");
				let mut command_stream = {
					log::info!("[Browser] Connecting to {} ...", command_addr);
					let stream = TcpStream::connect(command_addr).await.unwrap();
					let mut request = http::Request::new(());
					*request.uri_mut() =
						format!("ws://{}:{}{}", LOCALHOST, COMMAND_PORT, COMMAND_PATH)
							.parse()
							.unwrap();

					log::info!(
						"[Browser] Establishing websocket connection with request {:?} ...",
						request
					);
					websocket::connect_message_stream(stream, request)
						.await
						.unwrap()
				};

				log::info!("[Browser] Waiting for command...");
				let msg = command_stream.next().await.unwrap().unwrap();
				let cmd = if let Message::Text(cmd_str) = msg {
					serde_json::from_str::<Command>(&cmd_str).unwrap()
				} else {
					panic!("Wrong message type: {:?}", msg);
				};

				log::info!("[Browser] Command received: {:?}", cmd);
				let local_stream = {
					let uri = http::Uri::from_str(&cmd.src).unwrap();
					let addr = SocketAddr::from_str(uri.authority().unwrap().as_str()).unwrap();
					log::info!("[Browser] Connecting to {}", addr);
					let stream = TcpStream::connect(addr).await.unwrap();
					let mut request = http::Request::new(());
					*request.uri_mut() = uri;
					log::info!(
						"[Browser] Creating websocket connection with request {:?}",
						request
					);
					websocket::connect_stream(stream, request).await.unwrap()
				};

				let remote_uri = http::Uri::from_str(&cmd.dst).unwrap();
				assert_eq!(remote_uri.path(), SERVER_PATH);
				assert_eq!(
					remote_uri.authority().unwrap().as_str(),
					server_addr.to_string()
				);

				log::info!("[Browser] Proxying...");
				let (mut r, mut w) = tokio::io::split(local_stream);
				tokio::io::copy(&mut r, &mut w).await.unwrap();
			};

			let proxy_task = async move {
				log::info!("[Browser] Running proxy task");
				let settings = SettingsBuilder {
					server_path: SERVER_PATH.into(),
					use_wss: false,
					command_port: COMMAND_PORT,
					command_path: COMMAND_PATH.into(),
				}
				.build();
				let mut stream = settings.connect(&server_addr.into()).await.unwrap();

				log::info!("[Proxy] Writing payload...");
				stream.write_all(&PAYLOAD).await.unwrap();
				let mut buf = vec![0_u8; PAYLOAD.len()];
				log::info!("[Proxy] Receiving payload...");
				stream.read_exact(&mut buf).await.unwrap();
				assert_eq!(buf, PAYLOAD);
				log::info!("[Proxy] Shutting down connection.");
				stream.shutdown().await.unwrap();
				log::info!("[Proxy] Finish.");
			};

			futures::join!(proxy_task, browser_task);
		});
	}
}
