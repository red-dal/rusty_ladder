use super::{
	http_server, read_server_config, CloneAndPush, Tester, CHILD_INIT_TIME, HTTP_SERVER_ADDR,
	HTTP_SERVER_URL, SERVED_DATA,
};
use log::error;
use std::{error::Error as StdErr, net::SocketAddr, path::Path};

impl Tester {
	pub fn test_tcp_with_v2ray(
		&self,
		label: &str,
		v2_conf_path: &Path,
		conf_path: &Path,
		proxies: &[(&str, Option<(&str, &str)>)],
	) {
		let child = self.spawn_v2ray(v2_conf_path).unwrap();

		println!("Start TCP test for {}", label);
		println!(
			"Current directory: {}",
			std::env::current_dir().unwrap().display()
		);
		// Wait for child to initialize

		let server = read_server_config(conf_path).unwrap();

		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async move {
			let addr: SocketAddr = HTTP_SERVER_ADDR.parse().unwrap();
			let serve_task = tokio::spawn(async move {
				if let Err(err) = server.serve(None).await {
					error!("Proxy server exited with error ({}) ", err)
				}
			});
			let http_task = tokio::spawn(async move {
				if let Err(err) = http_server::serve(addr).await {
					error!("HTTP server exited with error ({}) ", err);
				}
			});

			// Wait for child process, http_task and serve_task to initialize
			tokio::time::sleep(CHILD_INIT_TIME).await;

			// inbound
			for (proxy, auth) in proxies {
				make_request(proxy, *auth).await.unwrap();
			}

			serve_task.abort();
			http_task.abort();
			assert!(serve_task.await.unwrap_err().is_cancelled());
			assert!(http_task.await.unwrap_err().is_cancelled());
		});

		println!("Finish testing {}, killing child process", label);
		child.kill_and_wait();
	}

	pub fn test_socks5(&self) {
		let socks_dir = self.test_config_dir.clone_push("socks");
		let v2_conf_path = socks_dir.clone_push("v2_in.json");
		let conf_path = socks_dir.clone_push("test.toml");

		// inbound
		println!("\n--------------------------- SOCKS5 Inbound ---------------------------\n");
		self.test_tcp_with_v2ray(
			"socks5_in",
			&v2_conf_path,
			&conf_path,
			&[
				("socks5://127.0.0.1:10000", None),
				("socks5://127.0.0.1:10000", Some(("user1", "user1password"))),
				("socks5://127.0.0.1:10001", Some(("user1", "user1password"))),
			],
		);
		// outbound
		println!("\n--------------------------- SOCKS5 Outbound ---------------------------\n");
		self.test_tcp_with_v2ray(
			"socks5_out",
			&v2_conf_path,
			&conf_path,
			&[
				("socks5://127.0.0.1:10002", None),
				("socks5://127.0.0.1:10003", None),
				("socks5://127.0.0.1:10004", None),
			],
		);
	}

	pub fn test_http(&self) {
		let http_dir = self.test_config_dir.clone_push("http");
		let v2_conf_file = http_dir.clone_push("v2_in.json");
		let conf_file = http_dir.clone_push("test.toml");

		println!("\n--------------------------- HTTP Inbound ---------------------------\n");
		self.test_tcp_with_v2ray(
			"http_in",
			&v2_conf_file,
			&conf_file,
			&[
				("http://127.0.0.1:10000", None),
				("http://127.0.0.1:10000", Some(("user1", "user1password"))),
				("http://127.0.0.1:10001", Some(("user1", "user1password"))),
			],
		);
		println!("\n--------------------------- HTTP Outbound ---------------------------\n");
		self.test_tcp_with_v2ray(
			"http_out",
			&v2_conf_file,
			&conf_file,
			&[
				("http://127.0.0.1:10002", None),
				("http://127.0.0.1:10003", Some(("user1", "user1password"))),
				("http://127.0.0.1:10004", Some(("user1", "user1password"))),
			],
		);
	}

	pub fn test_shadowsocks(&self) {
		let ss_dir = self.test_config_dir.clone_push("shadowsocks");

		println!("\n--------------------------- Shadowsocks Inbound ---------------------------\n");
		{
			let v2_conf_file = ss_dir.clone_push("in/v2_out.json");
			let conf_file = ss_dir.clone_push("in/in.toml");

			self.test_tcp_with_v2ray(
				"ss_in",
				&v2_conf_file,
				&conf_file,
				&[
					("socks5://127.0.0.1:10000", None),
					("socks5://127.0.0.1:10001", None),
					("socks5://127.0.0.1:10002", None),
					("socks5://127.0.0.1:10003", None),
				],
			);
		}
		println!(
			"\n--------------------------- Shadowsocks Outbound ---------------------------\n"
		);
		{
			let v2_conf_file = ss_dir.clone_push("out/v2_in.json");
			let conf_file = ss_dir.clone_push("out/out.toml");

			self.test_tcp_with_v2ray(
				"out",
				&v2_conf_file,
				&conf_file,
				&[
					("socks5://127.0.0.1:10000", None),
					("socks5://127.0.0.1:10001", None),
					("socks5://127.0.0.1:10002", None),
					("socks5://127.0.0.1:10003", None),
				],
			);
		}
	}

	pub fn test_vmess(&self) {
		let vmess_dir = self.test_config_dir.clone_push("vmess");

		{
			println!("\n--------------------------- VMess AEAD Inbound ---------------------------\n");
			let dir = vmess_dir.clone_push("tcp_in");
			let v2_conf_file = dir.clone_push("v2_out.json");
			let conf_file = dir.clone_push("in.toml");

			let mut proxies = vec![];

			proxies.extend([
				("socks5://127.0.0.1:10000", None),
				("socks5://127.0.0.1:10001", None),
				("socks5://127.0.0.1:10002", None),
				("socks5://127.0.0.1:10003", None),
			]);

			self.test_tcp_with_v2ray("vmess_in", &v2_conf_file, &conf_file, &proxies);
		}
		
		#[cfg(feature = "vmess-legacy-auth")]
		{
			println!("\n--------------------------- VMess Legacy Inbound ---------------------------\n");
			let dir = vmess_dir.clone_push("tcp_in");
			let v2_conf_file = dir.clone_push("legacy_v2_out.json");
			let conf_file = dir.clone_push("legacy_in.toml");

			let mut proxies = vec![];

			proxies.extend([
				("socks5://127.0.0.1:10000", None),
				("socks5://127.0.0.1:10001", None),
				("socks5://127.0.0.1:10002", None),
			]);

			self.test_tcp_with_v2ray("vmess_in", &v2_conf_file, &conf_file, &proxies);
		}

		{
			println!("\n--------------------------- VMess Outbound ---------------------------\n");
			let dir = vmess_dir.clone_push("tcp_out");
			let v2_conf_file = dir.clone_push("v2_in.json");
			let conf_file = dir.clone_push("out.toml");

			self.test_tcp_with_v2ray(
				"vmess_out",
				&v2_conf_file,
				&conf_file,
				&[
					("socks5://127.0.0.1:10000", None),
					("socks5://127.0.0.1:10001", None),
					("socks5://127.0.0.1:10002", None),
					("socks5://127.0.0.1:10003", None),
				],
			);
		}
	}

	pub fn test_chain(&self) {
		let transport_dir = self.test_config_dir.clone_push("chain");

		println!("\n--------------------------- Chain Outbound ---------------------------\n");
		{
			let v2_conf_file = transport_dir.clone_push("v2_in.json");
			let conf_file = transport_dir.clone_push("out.toml");

			self.test_tcp_with_v2ray(
				"chain",
				&v2_conf_file,
				&conf_file,
				&[("socks5://127.0.0.1:10000", None)],
			);
		}
	}
	
	pub fn test_transport(&self) {
		let transport_dir = self.test_config_dir.clone_push("transport");

		println!("\n--------------------------- Transport Inbound ---------------------------\n");
		{
			let v2_conf_file = transport_dir.clone_push("v2_out.json");
			let conf_file = transport_dir.clone_push("in.toml");

			self.test_tcp_with_v2ray(
				"transport_in",
				&v2_conf_file,
				&conf_file,
				&[
					("socks5://127.0.0.1:10000", None),
					("socks5://127.0.0.1:10001", None),
					("socks5://127.0.0.1:10002", None),
				],
			);
		}
		println!("\n--------------------------- Transport Outbound ---------------------------\n");
		{
			let v2_conf_file = transport_dir.clone_push("v2_in.json");
			let conf_file = transport_dir.clone_push("out.toml");

			self.test_tcp_with_v2ray(
				"transport_out",
				&v2_conf_file,
				&conf_file,
				&[
					("socks5://127.0.0.1:10000", None),
					("socks5://127.0.0.1:10001", None),
					("socks5://127.0.0.1:10002", None),
				],
			);
		}
	}
}

async fn make_request(proxy: &str, auth: Option<(&str, &str)>) -> Result<(), Box<dyn StdErr>> {
	println!(
		"\nMaking request for proxy {} with {}",
		proxy,
		AuthDisplayer(&auth)
	);

	let client = {
		let proxy = if let Some((username, password)) = auth {
			reqwest::Proxy::all(proxy)?.basic_auth(username, password)
		} else {
			reqwest::Proxy::all(proxy)?
		};
		reqwest::Client::builder().proxy(proxy).build()?
	};

	let response = client.get(HTTP_SERVER_URL).send().await?;
	let status = response.status();
	let data = response.bytes().await?;

	assert_eq!(SERVED_DATA.as_bytes(), data.as_ref());

	println!(
		"Request to proxy {} with {} completed. Server responded with status {} and {} bytes of data",
		proxy,
		AuthDisplayer(&auth),
		status,
		data.len()
	);

	Ok(())
}

struct AuthDisplayer<'a, 'b>(&'a Option<(&'b str, &'b str)>);

impl std::fmt::Display for AuthDisplayer<'_, '_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if let Some((username, password)) = self.0 {
			write!(f, "('{}', '{}')", username, password)
		} else {
			write!(f, "()")
		}
	}
}
