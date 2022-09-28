use super::{sha_then_hex, Command, Key};
use crate::{
	prelude::{BoxStdErr, CRLF},
	protocol::{
		inbound::{AcceptError, Handshake, SessionInfo, SimpleHandshake, StreamAcceptor},
		AsyncReadWrite, BufBytesStream, CompositeBytesStream, GetProtocolName, SocksAddr,
	},
	utils::{read_until, ChainedReadHalf},
};
use async_trait::async_trait;
use std::{
	collections::HashSet,
	convert::{TryFrom, TryInto},
	net::SocketAddr,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader};

const REQUEST_BUFFER_SIZE: usize = 1024;

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	pub passwords: Vec<String>,
	pub redir_addr: SocketAddr,
}

impl SettingsBuilder {
	/// Return a [`Settings`].
	///
	/// # Errors
	///
	/// Return error if `passwords` is empty or contains empty string.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		if self.passwords.is_empty() {
			return Err("must have at least one password".into());
		}
		let keys: Result<HashSet<Key>, BoxStdErr> = self
			.passwords
			.iter()
			.map(|p| {
				if p.is_empty() {
					return Err("cannot have empty password".into());
				}
				let key = sha_then_hex(p.as_bytes());
				Ok(key)
			})
			.collect();
		Ok(Settings {
			keys: keys?,
			redir_addr: self.redir_addr,
		})
	}
}

pub struct Settings {
	pub keys: HashSet<Key>,
	pub redir_addr: SocketAddr,
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		"trojan"
	}
}

#[async_trait]
impl StreamAcceptor for Settings {
	#[inline]
	async fn accept_stream<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		_info: SessionInfo,
	) -> Result<Handshake<'a>, AcceptError> {
		fn make_err<T>(
			r: impl 'static + AsyncRead + Unpin + Send + Sync,
			w: impl 'static + AsyncWrite + Unpin + Send + Sync,
			a: SocketAddr,
			e: impl Into<BoxStdErr>,
		) -> Result<T, AcceptError> {
			let stream = CompositeBytesStream { r, w };
			Err(AcceptError::ProtocolRedirect(Box::new(stream), a, e.into()))
		}

		let mut buf = [0u8; REQUEST_BUFFER_SIZE];
		let (r, w) = stream.split();
		let mut r = BufReader::new(r);

		let rb = if let Some(rb) = read_request(&mut r, &mut buf).await? {
			rb
		} else {
			let r = ChainedReadHalf::new(r, buf.as_slice().to_owned());
			return make_err(r, w, self.redir_addr, "request bytes too long for trojan");
		};
		let total_len = rb.total_len;

		let req = match try_parse_request(&rb, &self.keys) {
			Ok(req) => req,
			Err(e) => {
				let buf = &buf[..total_len];
				let r = ChainedReadHalf::new(r, buf.to_owned());
				return make_err(r, w, self.redir_addr, e);
			}
		};

		match req.cmd {
			Command::Connect => {
				let stream = BufBytesStream { r: Box::new(r), w };
				Ok(Handshake::Stream(
					Box::new(SimpleHandshake(stream)),
					req.addr,
				))
			}
			#[cfg(feature = "use-udp")]
			Command::UdpAssociate => Err(AcceptError::Protocol(
				"trojan udp inbound is not supported".into(),
			)),
		}
	}
}

impl Settings {}

struct RequestBytes<'a> {
	key: &'a [u8],
	req: &'a [u8],
	total_len: usize,
}

struct Request {
	cmd: Command,
	addr: SocksAddr,
}

fn try_parse_request(rb: &RequestBytes, keys: &HashSet<Key>) -> Result<Request, BoxStdErr> {
	// Key part
	let key: &[u8; 56] = rb
		.key
		.try_into()
		.map_err(|_| format!("expected key length 56, but get {}", rb.key.len()))?;
	if !keys.contains(key.as_slice()) {
		return Err("invalid key".into());
	}

	// Request part
	if rb.req.len() <= 4 {
		return Err("slice too small for trojan request".into());
	}

	let cmd = Command::try_from(rb.req[0])
		.map_err(|_e| "unknown value {} for command in trojan request")?;

	let addr_buf = &rb.req[1..];
	let (addr, len) = SocksAddr::read_from_bytes(addr_buf)?;
	let len = usize::from(len.get());
	if len < addr_buf.len() {
		return Err(format!(
			"slice has length of {len}, but only take {} bytes to parse address",
			addr_buf.len()
		)
		.into());
	}

	Ok(Request { cmd, addr })
}

async fn read_request(
	mut r: impl AsyncBufRead + Unpin,
	buf: &mut [u8],
) -> std::io::Result<Option<RequestBytes<'_>>> {
	let len = read_until(&mut r, CRLF, buf).await?.map(<[_]>::len);
	let len = if let Some(len) = len {
		len
	} else {
		return Ok(None);
	};

	let next_len = read_until(r, CRLF, &mut buf[len..]).await?.map(<[_]>::len);
	if let Some(nl) = next_len {
		let total_len = len + nl;
		let (key, req) = buf.split_at(len);
		Ok(Some(RequestBytes {
			key: &key[..key.len() - CRLF.len()],
			req: &req[..nl - CRLF.len()],
			total_len,
		}))
	} else {
		Ok(None)
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("trojan-in")
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "trojan-in({addr})", addr = &self.redir_addr)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		network::Addrs,
		protocol::{CompositeBytesStream, SocksAddr},
		proxy::trojan::{sha_then_hex, Command},
	};
	use std::str::FromStr;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	#[test]
	fn test_accept_stream() {
		const PASSWORD: &str = "password";
		const PAYLOAD: &[u8] = b"this is some data";
		const PAYLOAD_REPLY: &[u8] = b"this is a reply";

		let expected_redir_addr = SocketAddr::from_str("127.0.0.1:12345").unwrap();
		let dst_addr = SocksAddr::from_str("127.0.0.1:9999").unwrap();

		let settings = SettingsBuilder {
			passwords: vec![PASSWORD.into()],
			redir_addr: expected_redir_addr,
		}
		.build()
		.unwrap();

		let task = async move {
			let (mut a, stream) = tokio::io::duplex(8 * 1024);
			let stream = {
				let (r, w) = tokio::io::split(stream);
				Box::new(CompositeBytesStream { r, w })
			};
			// Write request
			{
				let mut buf = Vec::new();
				buf.extend_from_slice(sha_then_hex(PASSWORD.as_bytes()).as_ref());
				buf.extend_from_slice(CRLF);
				buf.push(Command::Connect as u8);
				dst_addr.write_to(&mut buf);
				buf.extend_from_slice(CRLF);

				a.write_all(&mut buf).await.unwrap();
			}
			// Handshake
			let hs = settings
				.accept_stream(
					stream,
					SessionInfo {
						addr: Addrs {
							peer: SocketAddr::from_str("127.0.0.1:7777").unwrap(),
							local: SocketAddr::from_str("127.0.0.1:8888").unwrap(),
						},
						is_transport_empty: false,
					},
				)
				.await;
			let finish = match hs {
				Ok(hs) => match hs {
					Handshake::Stream(stream, addr) => {
						assert_eq!(addr, dst_addr);
						stream
					}
					Handshake::Datagram(_) => panic!("Wrong handshake type"),
				},
				Err(e) => {
					panic!("{}", e);
				}
			};
			let mut stream = finish.finish().await.unwrap();
			// Test stream
			let mut buf = [0u8; 4096];
			{
				a.write_all(PAYLOAD).await.unwrap();
				let len = stream.read(&mut buf).await.unwrap();
				assert_eq!(&buf[..len], PAYLOAD);
			}
			{
				stream.write_all(PAYLOAD_REPLY).await.unwrap();
				let len = a.read(&mut buf).await.unwrap();
				assert_eq!(&buf[..len], PAYLOAD_REPLY);
			}
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}

	#[test]
	fn test_accept_stream_failed() {
		const PAYLOAD: &[u8] = b"this is some data";
		const PAYLOAD_REPLY: &[u8] = b"this is a reply";

		let expected_redir_addr = SocketAddr::from_str("127.0.0.1:12345").unwrap();
		let dst_addr = SocksAddr::from_str("127.0.0.1:9999").unwrap();

		let settings = SettingsBuilder {
			passwords: vec!["password".into()],
			redir_addr: expected_redir_addr,
		}
		.build()
		.unwrap();

		let task = async move {
			let (mut a, stream) = tokio::io::duplex(8 * 1024);
			let stream = {
				let (r, w) = tokio::io::split(stream);
				Box::new(CompositeBytesStream { r, w })
			};
			// Write request
			let req_buf = {
				let mut buf = Vec::new();
				buf.extend_from_slice(sha_then_hex(b"not the correct password").as_ref());
				buf.extend_from_slice(CRLF);
				buf.push(Command::Connect as u8);
				dst_addr.write_to(&mut buf);
				buf.extend_from_slice(CRLF);

				a.write_all(&mut buf).await.unwrap();
				buf
			};
			// Handshake
			let hs = settings
				.accept_stream(
					stream,
					SessionInfo {
						addr: Addrs {
							peer: SocketAddr::from_str("127.0.0.1:7777").unwrap(),
							local: SocketAddr::from_str("127.0.0.1:8888").unwrap(),
						},
						is_transport_empty: false,
					},
				)
				.await;
			let mut stream = match hs {
				Ok(_hs) => {
					panic!("handshake should get an error");
				}
				Err(e) => {
					if let AcceptError::ProtocolRedirect(stream, redir_addr, _e) = e {
						assert_eq!(redir_addr, expected_redir_addr);
						stream
					} else {
						panic!("Wrong type of AcceptError");
					}
				}
			};

			// Test stream
			let mut buf = [0u8; 4096];
			let len = stream.read(&mut buf).await.unwrap();
			assert_eq!(&buf[..len], req_buf);
			{
				a.write_all(PAYLOAD).await.unwrap();
				let len = stream.read(&mut buf).await.unwrap();
				assert_eq!(&buf[..len], PAYLOAD);
			}
			{
				stream.write_all(PAYLOAD_REPLY).await.unwrap();
				let len = a.read(&mut buf).await.unwrap();
				assert_eq!(&buf[..len], PAYLOAD_REPLY);
			}
		};
		tokio::runtime::Runtime::new().unwrap().block_on(task);
	}
}
