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

/*!
 * Traffic will go through:
 * ```not_rust
 * +--------------+                +----------------+
 * |              |    tunnel      |                |
 * |              +--------------->| Proxy Outbound |
 * |              |                |                |
 * |              |                +-------+--------+
 * | SpeedTester  |                        |
 * |              |                        | direct/Shadowsocks/VMess
 * |              |                        v
 * |              |               +-----------------+
 * |              |    freedom    |                 |
 * |              |<--------------+  Proxy Inbound  |
 * +--------------+               |                 |
 *                                +-----------------+
 * ```
 */

mod server;

use server::Counter;
use std::{borrow::Cow, convert::TryInto, fmt::Display, net::SocketAddr, time::Duration};
use tokio::runtime::Runtime;

/// Number of packets to be sent for each test.
///
/// Each packet is 8KB.
const TEST_TOTAL_PACKETS: usize = 32 * 1024; // 4GB in total

/// A list of (postfix, connection count).
const TEST_COUNTS: &[(&str, usize)] = &[("1", 1), ("4", 4), ("32", 32), ("128", 128)];

#[derive(serde::Deserialize, Debug)]
struct Config {
	/// Address of test server.
	server_addr: SocketAddr,
	/// List of (test_name, port to test).
	test_addrs: Vec<(String, SocketAddr)>,
}

fn main() {
	let cmd_args = std::env::args().collect::<Vec<String>>();
	println!("Commandline arguments: {:?}", cmd_args);

	let config_path = if cmd_args.len() >= 2 {
		cmd_args[1].clone()
	} else {
		panic!("Must have at least one arguments");
	};

	let config_str = std::fs::read_to_string(&config_path).unwrap();
	let config: Config = toml::from_str(&config_str).unwrap();

	let all_res = test(config.server_addr, config.test_addrs.into_iter());
	println!("{}", format_table(&all_res));
}

fn test(
	server_addr: SocketAddr,
	test_ports: impl Iterator<Item = (String, SocketAddr)>,
) -> Vec<TestResult> {
	let mut all_res = Vec::new();

	for (test_name, client_server_addr) in test_ports {
		// 8KB for each packets.
		let mut res = Vec::new();
		println!("Testing {}", client_server_addr);

		for &(postfix, conn_count) in TEST_COUNTS {
			let echo_count = TEST_TOTAL_PACKETS / conn_count;
			let args = server::TestArgs {
				conn_count,
				echo_count,
				reverse: false,
				server_addr,
				client_server_addr,
			};
			let tag = format!("{}-{}", test_name, postfix);
			let (elapsed, aver_speed) = test_with_args(&args, &tag);
			res.push(TestResult {
				name: tag,
				elapsed_ms: elapsed.as_millis().try_into().unwrap(),
				aver_speed,
			});
		}

		all_res.extend(res);
	}
	all_res
}

#[derive(Debug)]
struct TestResult {
	name: String,
	elapsed_ms: u64,
	aver_speed: f64,
}

fn format_table(results: &[TestResult]) -> String {
	use std::fmt::Write;
	const HEADERS: &[&str] = &["name", "elapsed_ms", "aver_speed"];

	let rows: Vec<[String; 3]> = results
		.iter()
		.map(|res| {
			[
				res.name.clone(),
				res.elapsed_ms.to_string(),
				format!("{}/s", BytesCount(res.aver_speed as u64)),
			]
		})
		.collect();
	// Calculate width for each columns.

	let widths = {
		let mut widths = [0_usize; 3];
		for (h, width) in HEADERS.iter().zip(widths.iter_mut()) {
			*width = std::cmp::max(*width, h.len());
		}
		for cols in &rows {
			for (col, width) in cols.iter().zip(widths.iter_mut()) {
				*width = std::cmp::max(*width, col.len());
			}
		}
		widths
	};
	// Draw headers.
	let mut table = String::new();
	for (&header, width) in HEADERS.iter().zip(widths) {
		write!(table, "| {} ", AlignHelper(header.into(), width)).unwrap();
	}
	writeln!(table, "|").unwrap();
	for (_, width) in HEADERS.iter().zip(widths) {
		write!(table, "| {}: ", "-".repeat(width - 1)).unwrap();
	}
	writeln!(table, "|").unwrap();
	// Draw rows.
	for cols in rows {
		let mut count = 0;
		#[allow(clippy::explicit_counter_loop)]
		for col in cols {
			write!(table, "| {} ", AlignHelper(col.into(), widths[count])).unwrap();
			count += 1;
		}
		writeln!(table, "|").unwrap();
	}
	table
}

struct AlignHelper(Cow<'static, str>, usize);

impl Display for AlignHelper {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if let Some(diff) = self.1.checked_sub(self.0.len()) {
			write!(f, "{}", " ".repeat(diff))?;
		}
		write!(f, "{}", self.0)
	}
}

#[must_use]
fn test_with_args(args: &server::TestArgs, tag: &str) -> (Duration, f64) {
	let counter = Counter::default();

	println!("Start testing '{}' with {:#?}", tag, args);

	let rt = Runtime::new().expect("cannot create a new runtime");
	let elapsed = rt.block_on(args.test(counter.clone()));
	let elapsed_secs = elapsed.as_secs_f64();

	let speed = counter.get() as f64 / elapsed_secs;

	println!(
		"Transferred bytes: {}, elapsed: {}ms, average speed: {}/s\n",
		BytesCount(counter.get()),
		elapsed.as_millis(),
		BytesCount(speed as u64)
	);

	(elapsed, speed)
}

struct BytesCount(u64);

impl BytesCount {
	const UNIT_NAMES: &'static [&'static str] = &["B", "KB", "MB", "GB", "TB"];
	const STEP: u16 = 1024;
}

impl Display for BytesCount {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let val = self.0 as f64;
		let log_val = val.log(Self::STEP as f64) as usize;
		let name = Self::UNIT_NAMES[log_val as usize];
		let base = (Self::STEP as f64).powi(log_val as i32);

		let new_val = val / base;

		write!(f, "{:.2} {}", new_val, name)
	}
}
