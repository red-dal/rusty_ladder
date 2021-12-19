use super::{
	read_server_config, CloneAndPush, Tester, CHILD_INIT_TIME, UDP_ECHO_ADDR, UDP_PROXY_ADDR,
};
use log::debug;
use std::{io, net::SocketAddr, path::Path, time::Duration};
use tokio::net::UdpSocket;

type BoxStdErr = Box<dyn std::error::Error + Send + Sync>;

const UDP_PACKET_NUM_EACH_TUNNEL: usize = 16;
const UDP_TUNNEL_NUM: usize = 2;
const UDP_RETRY_COUNT: usize = 3;
const UDP_TIMEOUT: Duration = Duration::from_millis(500);

impl Tester {
	pub fn test_udp_tunnel(&self) {
		println!("\n--------------------------- Tunnel UDP Inbound ---------------------------\n");
		let tunnel_dir = self.test_config_dir.clone_push("tunnel");
		let conf_path = tunnel_dir.clone_push("test.toml");
		self.test_udp_with_v2ray("Tunnel UDP inbound", &conf_path, None);
	}

	#[cfg(feature = "socks5-inbound")]
	pub fn test_udp_socks(&self) {
		println!("\n--------------------------- SOCKS5 UDP Inbound ---------------------------\n");
		let socks_dir = self.test_config_dir.clone_push("socks");
		let conf_path = socks_dir.clone_push("udp_in.toml");
		let v2_udp_path = socks_dir.clone_push("v2_udp_out.json");
		self.test_udp_with_v2ray("SOCKS UDP inbound", &conf_path, Some(v2_udp_path.as_ref()));
	}

	#[cfg(any(
		feature = "vmess-inbound-openssl",
		feature = "vmess-inbound-ring",
		feature = "vmess-outbound-openssl",
		feature = "vmess-outbound-ring"
	))]
	pub fn test_udp_vmess(&self) {
		println!("\n--------------------------- VMess UDP Inbound ---------------------------\n");
		{
			let vmess_dir = self.test_config_dir.clone_push("vmess/udp_in");
			let conf_path = vmess_dir.clone_push("in.toml");
			let v2_conf_path = vmess_dir.clone_push("v2_out.json");
			self.test_udp_with_v2ray("VMess UDP inbound", &conf_path, Some(v2_conf_path.as_ref()));
		}
		println!("\n--------------------------- VMess UDP Outbound ---------------------------\n");
		{
			let vmess_dir = self.test_config_dir.clone_push("vmess/udp_out");
			let conf_path = vmess_dir.clone_push("out.toml");
			let v2_conf_path = vmess_dir.clone_push("v2_in.json");
			self.test_udp_with_v2ray(
				"VMess UDP outbound",
				&conf_path,
				Some(v2_conf_path.as_ref()),
			);
		}
	}

	/// Proxy will goes through  -> Proxy server [32211] -> Ehco server [9876]
	fn test_udp_with_v2ray(&self, label: &str, conf_path: &Path, v2_conf_path: Option<&Path>) {
		let child = v2_conf_path.map(|v2_conf_path| self.spawn_v2ray(v2_conf_path).unwrap());

		println!("Start UDP test for [{}]", label);
		println!(
			"Current directory: {}",
			std::env::current_dir().unwrap().display()
		);

		let server = read_server_config(conf_path).unwrap();
		let rt = tokio::runtime::Runtime::new().expect("Cannot spawn tokio runtion");
		rt.block_on(async move {
			// Initializing tasks
			let serve_task = tokio::spawn(async move {
				server
					.serve(None)
					.await
					.expect("Error occurred when serving.");
			});
			let echo_task = tokio::spawn(async move {
				serve_udp_echo(UDP_ECHO_ADDR.into())
					.await
					.expect("Error occurred when serving UDP");
			});

			// Wait for child process, http_task and serve_task to initialize
			tokio::time::sleep(CHILD_INIT_TIME).await;

			test_udp_echo(UDP_PROXY_ADDR.into())
				.await
				.expect("Error when testing UDP echo server");

			// Shutting down tasks
			serve_task.abort();
			echo_task.abort();
			assert!(serve_task.await.unwrap_err().is_cancelled());
			assert!(echo_task.await.unwrap_err().is_cancelled());
		});

		if let Some(child) = child {
			child.kill_and_wait()
		};
	}
}

async fn serve_udp_echo(addr: SocketAddr) -> io::Result<()> {
	loop {
		let sock = UdpSocket::bind(addr).await?;
		let mut buf = vec![0_u8; 4096];
		let (len, src) = sock.recv_from(&mut buf).await?;
		debug!("Echo server receive packet from {}", src);
		if len == 0 {
			break;
		}
		sock.send_to(&buf[..len], src).await?;
	}
	Ok(())
}

async fn test_udp_echo(server_addr: SocketAddr) -> Result<(), BoxStdErr> {
	// Use one for now
	let mut tasks = Vec::with_capacity(UDP_TUNNEL_NUM);
	for ind in 0..UDP_TUNNEL_NUM {
		let wait_dur = Duration::from_millis(50 * ind as u64);
		let sock = UdpSocket::bind(SocketAddr::new([127, 0, 0, 1].into(), 0)).await?;
		tasks.push(test_udp_echo_single(sock, server_addr, wait_dur));
	}
	futures::future::try_join_all(tasks).await?;
	Ok(())
}

async fn test_udp_echo_single(
	sock: UdpSocket,
	server_addr: SocketAddr,
	wait_dur: Duration,
) -> Result<(), BoxStdErr> {
	// Sleep to avoid packet loss
	tokio::time::sleep(wait_dur).await;

	let bind_addr = sock.local_addr()?;
	debug!("Testing UdpSocket on {}", bind_addr);

	let msgs: Vec<String> = (0..UDP_PACKET_NUM_EACH_TUNNEL)
		.map(|ind| {
			format!(
				"This is message {} from {} to {}",
				ind, bind_addr, server_addr
			)
		})
		.collect();

	for msg in &msgs {
		let mut buf = vec![0_u8; 256];
		// Retry several times until a packet is received
		let (len, dst) = {
			let mut loop_result = None;
			for _ in 0..UDP_RETRY_COUNT {
				debug!("Sending message: {}", msg);
				sock.send_to(msg.as_bytes(), server_addr).await?;

				debug!("Receiving message on {}...", bind_addr);

				match tokio::time::timeout(UDP_TIMEOUT, sock.recv_from(&mut buf)).await {
					Ok(result) => {
						loop_result = Some(result?);
						break;
					}
					Err(_timeout) => {
						// Try again
					}
				}
			}
			if let Some(loop_result) = loop_result {
				loop_result
			} else {
				return Err(format!("UdpSocket on {} received no packet", bind_addr).into());
			}
		};
		let recv_msg = std::str::from_utf8(&buf[..len])?;
		debug!("{} Received message from {}: {}", bind_addr, dst, recv_msg);

		if msg != recv_msg {
			return Err(format!("Expected message '{}', but received '{}'", msg, recv_msg).into());
		}
	}

	Ok(())
}
