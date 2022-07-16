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

use super::{
	utils::{
		check_version, AcceptableMethod, Authentication, CommandCode, Error, Reply, ReplyCode,
		Request, SocksOrIoError, AUTH_FAILED, AUTH_SUCCESSFUL, SUB_VERS, VER5,
	},
	PROTOCOL_NAME,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::{
			AcceptError, AcceptResult, FinishHandshake, HandshakeError, SessionInfo, TcpAcceptor,
		},
		outbound::Error as OutboundError,
		AsyncReadWrite, BufBytesStream, GetProtocolName,
	},
};
use log::trace;
use std::{collections::HashMap, io};

const HANDSHAKE_BUFFER_CAPACITY: usize = 512;

// --------------------------------------------------------------
//                         Builder
// --------------------------------------------------------------

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct SettingsBuilder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub users: HashMap<String, String>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub is_udp_enabled: bool,
}

impl SettingsBuilder {
	/// Creates a SOCKS5 inbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		#[cfg(not(feature = "use-udp"))]
		if self.is_udp_enabled {
			return Err("`use-udp` feature must be enabled in order to use SOCKS5 UDP".into());
		}
		let settings = Settings::new(self.users);
		#[cfg(feature = "use-udp")]
		let settings = {
			let mut settings = settings;
			settings.is_udp_enabled = true;
			settings
		};
		Ok(settings)
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// socks5://[user:pass@]bind_addr:bind_port
	/// ```
	/// where `user` and `pass` is the percent encoded
	/// username and password for proxy authentication.
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;
		let users = crate::utils::url::get_user_pass(url)?.into_iter().collect();
		Ok(SettingsBuilder {
			users,
			is_udp_enabled: false,
		})
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("socks5-in")?;
		let mut empty = true;
		if self.is_udp_enabled {
			if empty {
				f.write_str("(")?;
			}
			empty = false;
			f.write_str("udp")?;
		}
		if !self.users.is_empty() {
			if empty {
				f.write_str("(")?;
			} else {
				f.write_str(",")?;
			}
			empty = false;
			f.write_str("auth")?;
		}
		if !empty {
			f.write_str(")")?;
		}
		Ok(())
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("socks5-in")?;
		let mut empty = true;
		if self.is_udp_enabled {
			if empty {
				f.write_str("(")?;
			}
			empty = false;
			f.write_str("udp")?;
		}
		if !self.users.is_empty() {
			if empty {
				f.write_str("(")?;
			} else {
				f.write_str(",")?;
			}
			empty = false;
			f.write_str("users:[")?;
			let mut users: Vec<&String> = self.users.iter().map(|(user, _pass)| user).collect();
			users.sort_unstable();
			crate::utils::fmt_iter(f, users.iter())?;
			f.write_str("]")?;
		}
		if !empty {
			f.write_str(")")?;
		}
		Ok(())
	}
}

// --------------------------------------------------------------
//                         Settings
// --------------------------------------------------------------

#[derive(Default)]
pub struct Settings {
	users: HashMap<String, String>,
	#[cfg(feature = "use-udp")]
	pub is_udp_enabled: bool,
}

impl Settings {
	#[inline]
	pub fn new(users: impl IntoIterator<Item = (String, String)>) -> Self {
		let users = users.into_iter().collect();
		Self {
			users,
			#[cfg(feature = "use-udp")]
			is_udp_enabled: false,
		}
	}

	#[inline]
	#[must_use]
	pub fn new_no_auth() -> Self {
		Self::new(Vec::new())
	}

	async fn perform_userpass_authentication(
		&self,
		stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
	) -> Result<bool, SocksOrIoError> {
		// Username/password authentication
		// See more at <https://datatracker.ietf.org/doc/html/rfc1929>
		debug!("Performing SOCKS5 username/password authentication.");
		let auth = Authentication::read(stream).await?;
		let mut success = false;
		if let Some(correct_pass) = self.users.get(auth.user.as_ref()) {
			if auth.pass.as_ref() == correct_pass.as_bytes() {
				success = true;
			}
		}
		trace!("SOKCS5 authentication done");
		// Reply to client
		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+
		let status = if success {
			AUTH_SUCCESSFUL
		} else {
			AUTH_FAILED
		};
		stream.write_all(&[SUB_VERS, status]).await?;
		// Break connection if authentication failed
		Ok(success)
	}
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpAcceptor for Settings {
	#[inline]
	async fn accept_tcp<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		info: SessionInfo,
	) -> Result<AcceptResult<'a>, AcceptError> {
		debug!("Performing SOCKS5 handshake with client ({info:?})...");
		let mut stream = BufBytesStream::from(stream);
		let mut buf = Vec::with_capacity(HANDSHAKE_BUFFER_CAPACITY);
		{
			let methods = Methods::read(&mut stream, &mut buf).await?;
			let acceptable_method = methods.choose(!self.users.is_empty());
			if let Some(acceptable_method) = acceptable_method {
				stream.write_all(&[VER5, acceptable_method as u8]).await?;
				match acceptable_method {
					AcceptableMethod::NoAuthentication => {
						// Do nothing
					}
					AcceptableMethod::UsernamePassword => {
						let success = self.perform_userpass_authentication(&mut stream).await?;
						if !success {
							return Err(AcceptError::Protocol(Error::FailedAuthentication.into()));
						}
					}
				}
			} else {
				stream.write_all(&[VER5, AUTH_FAILED]).await?;
				return Err(AcceptError::Protocol(
					Error::UnsupportedMethod(methods.0.into()).into(),
				));
			}
		}
		debug!("Reading SOCKS5 request...");
		let request = Request::read(&mut stream).await?;
		let cmd = request.code;
		let cmd = if let Ok(cmd) = CommandCode::try_from(cmd) {
			cmd
		} else {
			return Err(reply_error(
				&mut stream,
				request.addr.clone(),
				ReplyCode::CommandNotSupported,
				Error::UnknownCommand(cmd),
				&mut buf,
			)
			.await);
		};
		debug!(
			"SOCKS5 request successfully read, cmd: {}, dst: {}",
			cmd, request.addr
		);

		match cmd {
			CommandCode::Connect => {
				// Do nothing
			}
			CommandCode::Bind => {
				// BIND command not supported
				return Err(reply_error(
					&mut stream,
					request.addr.clone(),
					ReplyCode::CommandNotSupported,
					Error::UnsupportedCommand(cmd),
					&mut buf,
				)
				.await);
			}
			CommandCode::Udp => {
				#[cfg(feature = "use-udp")]
				{
					return self
						.handle_udp(
							stream,
							request,
							&mut buf,
							&info.addr.local,
							info.is_transport_empty,
						)
						.await;
				}
				#[cfg(not(feature = "use-udp"))]
				{
					// UDP not supported unless `use-udp` feature is enabled.
					return Err(reply_error(
						&mut stream,
						request.addr.clone(),
						ReplyCode::CommandNotSupported,
						Error::UnsupportedCommand(cmd),
						&mut buf,
					)
					.await);
				}
			}
		}
		// Send reply later
		Ok(AcceptResult::Tcp(
			Box::new(HandshakeHandle { inner: stream }),
			request.addr,
		))
	}
}

async fn reply_error<W: AsyncWrite + Unpin>(
	w: &mut W,
	addr: SocksAddr,
	code: ReplyCode,
	err: Error,
	buf: &mut Vec<u8>,
) -> AcceptError {
	debug!("Error during SOCKS5 handshake: {}", err);
	Reply {
		code: code as u8,
		addr,
	}
	.write_into(buf);
	if let Err(e) = w.write_all(buf).await {
		debug!("IO error when trying to reply to SOCKS5 client: {}", e);
		return AcceptError::from(e);
	}
	AcceptError::Protocol(err.into())
}

#[cfg(feature = "use-udp")]
mod udp {
	use super::{
		reply_error, AcceptError, AcceptResult, Error, Reply, ReplyCode, Request, Settings,
	};
	use crate::{
		prelude::BoxStdErr,
		protocol::{inbound::udp, AsyncReadWrite, BufBytesStream, SocksAddr, SocksDestination},
		utils::ReadInt,
	};
	use async_trait::async_trait;
	use futures::{future::AbortHandle, pin_mut};
	use log::{debug, trace, warn};
	use std::{
		io,
		net::{IpAddr, SocketAddr},
		sync::{
			atomic::{AtomicBool, Ordering},
			Arc,
		},
	};
	use tokio::{io::AsyncWriteExt, sync::Notify};

	const MIN_DATAGRAM_BUF_SIZE: usize = 512;

	impl Settings {
		pub(super) async fn handle_udp<'a>(
			&'a self,
			mut stream: BufBytesStream,
			request: Request,
			buf: &mut Vec<u8>,
			local_addr: &SocketAddr,
			is_transport_empty: bool,
		) -> Result<AcceptResult<'a>, AcceptError> {
			if is_transport_empty {
				// Do nothing
			} else {
				return Err(reply_error(
					&mut stream,
					request.addr.clone(),
					ReplyCode::CommandNotSupported,
					Error::Custom("transport cannot be used with UDP".into()),
					buf,
				)
				.await);
			}
			// UDP datagram will be sent from this address.
			let target_addr = {
				let src_ip = if let SocksDestination::Ip(ip) = &request.addr.dest {
					*ip
				} else {
					return Err(reply_error(
						&mut stream,
						request.addr.clone(),
						ReplyCode::AddressTypeNotSupported,
						Error::Custom("DST.ADDR must be an IP in UDP".into()),
						buf,
					)
					.await);
				};
				SocketAddr::new(src_ip, request.addr.port)
			};
			debug!(
				"SOCKS5 client ask for UDP proxying. Datagrams will be sent to {}.",
				target_addr
			);
			let (sock_builder, udp_relay_addr) = SocketWrapperBuilder::new(local_addr.ip()).await?;
			// Reply immediately.
			// TODO: Maybe add FinishHandshake for UDP later?
			Reply {
				code: ReplyCode::Succeeded as u8,
				addr: udp_relay_addr.into(),
			}
			.write_into(buf);
			stream.write_all(buf).await?;
			let sock = sock_builder.build(stream);

			debug!(
				"SOCKS5 server ready to proxy UDP datagrams on {}.",
				udp_relay_addr
			);

			return Ok(AcceptResult::Udp(sock));
		}
	}

	struct SocketWrapperBuilder {
		sock: Arc<tokio::net::UdpSocket>,
		shutdown_notify: Arc<Notify>,
	}

	impl SocketWrapperBuilder {
		async fn new(bind_ip: IpAddr) -> io::Result<(Self, SocketAddr)> {
			let sock = tokio::net::UdpSocket::bind((bind_ip, 0)).await?;
			let udp_relay_addr = sock.local_addr()?;
			Ok((
				Self {
					sock: Arc::new(sock),
					shutdown_notify: Arc::new(Notify::new()),
				},
				udp_relay_addr,
			))
		}

		fn build(self, mut stream: impl 'static + AsyncReadWrite) -> udp::DatagramStream {
			use tokio::io::AsyncReadExt;
			let is_shutdown = Arc::new(AtomicBool::new(false));

			let is_shutdown_clone = is_shutdown.clone();
			let shutdown_notify = self.shutdown_notify.clone();

			let (task, handle) = futures::future::abortable(async move {
				let is_shutdown = is_shutdown_clone;
				let mut buf = [0_u8; 512];
				loop {
					if is_shutdown.load(Ordering::Relaxed) {
						break;
					}
					match stream.read(&mut buf).await {
						Ok(n) => {
							if n == 0 {
								debug!("SOCKS5 TCP stream reached EOF, shutting down UDP");
								stream.shutdown().await.unwrap_or_default();
								break;
							}
							debug!(
								"SOCKS5 TCP stream read {} bytes during UDP, this shouldn't have happened.", n);
						}
						Err(err) => {
							debug!("SOCKS5 TCP stream encounter an error during UDP: {}", err);
							break;
						}
					}
				}
				// Do nothing for now
				shutdown_notify.notify_one();
				is_shutdown.store(true, Ordering::Relaxed);
			});
			tokio::spawn(task);
			SocketWrapper {
				sock: self.sock,
				shutdown_notify: self.shutdown_notify,
				is_shutdown,
				stream_abort_handle: handle,
			}
			.into()
		}
	}

	#[derive(Clone)]
	struct SocketWrapper {
		sock: Arc<tokio::net::UdpSocket>,
		shutdown_notify: Arc<Notify>,
		is_shutdown: Arc<AtomicBool>,
		stream_abort_handle: AbortHandle,
	}

	impl Drop for SocketWrapper {
		fn drop(&mut self) {
			self.is_shutdown.store(true, Ordering::Relaxed);
			self.stream_abort_handle.abort();
		}
	}

	impl SocketWrapper {
		fn handle_datagram(
			buf: &mut [u8],
			src_addr: SocketAddr,
		) -> Result<udp::DatagramInfo, BoxStdErr> {
			use std::convert::TryFrom;

			// UDP datagram format:
			//
			// +----+------+------+----------+----------+----------+
			// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
			// +----+------+------+----------+----------+----------+
			// | 2  |  1   |  1   | Variable |    2     | Variable |
			// +----+------+------+----------+----------+----------+
			//
			// See more at https://datatracker.ietf.org/doc/html/rfc1928#section-7
			// Datagram must be at least this large.
			if buf.len() <= 2 + 1 + 1 + 2 {
				return Err("SOCKS5 UDP request datagram too small".into());
			}

			let (dst, pos) = {
				let mut cursor = std::io::Cursor::new(&*buf);
				// Reserved, can be ignored.
				let _rsv = cursor.read_u16()?;
				// Whether or not this datagram is one of a number of fragments.
				// Fragmentation is not supported, so this must be 0.
				let frag = cursor.read_u8()?;
				if frag != 0 {
					return Err(
						"FRAG in SOCKS5 UDP datagram request is not 0 but fragmentation is not supported.".into());
				}
				let dst = SocksAddr::read_from(&mut cursor)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

				let pos = usize::try_from(cursor.position()).unwrap();
				(dst, pos)
			};
			let data_len = buf.len() - pos;
			if data_len == 0 {
				return Err(format!("Empty datagram to {}", dst).into());
			}
			// Copy data to the front of buf
			buf.copy_within(pos.., 0);

			debug!(
				"Received SOCKS5 datagram of {} bytes from {} to '{}'",
				data_len, src_addr, dst
			);

			let info = udp::DatagramInfo {
				len: data_len,
				src: Some(src_addr),
				dst,
			};

			Ok(info)
		}
	}

	#[async_trait]
	impl udp::RecvDatagram for SocketWrapper {
		async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<udp::DatagramInfo> {
			if buf.len() < MIN_DATAGRAM_BUF_SIZE {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"buf is too small for SOCKS5 datagram",
				));
			}
			if self.is_shutdown.load(Ordering::Relaxed) {
				return Err(io::Error::new(
					io::ErrorKind::BrokenPipe,
					"SOCKS5 UDP connection already closed",
				));
			}
			loop {
				let (len, src_addr): (usize, SocketAddr) = {
					let recv_task = self.sock.recv_from(buf);
					let notify_task = self.shutdown_notify.notified();
					pin_mut!(recv_task);
					pin_mut!(notify_task);
					match futures::future::select(recv_task, notify_task).await {
						futures::future::Either::Left((res, _)) => res?,
						futures::future::Either::Right(_) => {
							return Err(io::Error::new(
								io::ErrorKind::BrokenPipe,
								"SOCKS5 TCP connection dropped",
							));
						}
					}
				};
				trace!("Received datagram of {} bytes from {}", len, src_addr);
				match Self::handle_datagram(&mut buf[..len], src_addr) {
					Ok(info) => return Ok(info),
					Err(e) => {
						// Only log the invalid datagram.
						warn!("Invalid SOCKS5 UDP request datagram ({}).", e);
						continue;
					}
				}
			}
		}
	}

	#[async_trait]
	impl udp::SendDatagram for SocketWrapper {
		async fn send_inbound(&mut self, sess: &udp::Session, data: &[u8]) -> io::Result<usize> {
			use bytes::BufMut;
			if self.is_shutdown.load(Ordering::Relaxed) {
				return Err(io::Error::new(
					io::ErrorKind::BrokenPipe,
					"SOCKS5 UDP connection already closed",
				));
			}
			let mut buf = [0_u8; 512];
			debug!(
				"Sending SOCKS5 datagram back to client on session {:?}",
				sess
			);
			// Checking data.len()
			let expected_header_len = 3 + sess.dst.serialized_len_atyp();
			if data.len() + expected_header_len > buf.len() {
				let msg = format!(
					"data.len() too large, must be smaller than {} (buf size) - {} (header size)",
					data.len(),
					expected_header_len
				);
				return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
			}
			// Formatting datagram
			let remaining_len = {
				let mut writer = buf.as_mut();
				// Reserve (2 bytes) and fragmentation number (1 bytes), both zero.
				writer.put_slice(&[0_u8, 0_u8, 0_u8]);
				sess.dst.write_to(&mut writer);
				writer.put_slice(data);
				writer.len()
			};
			let pos = buf.len() - remaining_len;
			// Sending datagram
			self.sock.send_to(&buf[..pos], sess.src).await
		}
	}

	impl From<SocketWrapper> for udp::DatagramStream {
		fn from(socket: SocketWrapper) -> Self {
			let r = Box::new(socket.clone());
			let w = Box::new(socket);
			Self {
				read_half: r,
				write_half: w,
			}
		}
	}
}

struct HandshakeHandle {
	pub inner: BufBytesStream,
}

#[async_trait]
impl FinishHandshake for HandshakeHandle {
	async fn finish(mut self: Box<Self>) -> Result<BufBytesStream, HandshakeError> {
		write_reply(&mut self.inner, ReplyCode::Succeeded).await?;
		Ok(self.inner)
	}

	async fn finish_err(mut self: Box<Self>, err: &OutboundError) -> Result<(), HandshakeError> {
		let reply_code = match err {
			OutboundError::Io(_) => ReplyCode::ConnectionsRefused,
			OutboundError::NotResolved(_) => ReplyCode::HostUnreachable,
			OutboundError::NotAllowed => ReplyCode::NotAllowedByRuleset,
			_ => ReplyCode::SocksFailure,
		};
		debug!(
			"Sending SOCKS5 reply to client with code {}({}) because of outbound error ({})",
			reply_code.val(),
			reply_code,
			err
		);
		write_reply(&mut self.inner, reply_code).await
	}
}

async fn write_reply<W: AsyncWrite + Unpin>(
	w: &mut W,
	reply_code: ReplyCode,
) -> Result<(), HandshakeError> {
	let mut buf = Vec::with_capacity(HANDSHAKE_BUFFER_CAPACITY);
	let empty_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
	Reply {
		code: reply_code as u8,
		addr: empty_addr.into(),
	}
	.write_into(&mut buf);
	w.write_all(&buf).await?;
	if reply_code != ReplyCode::Succeeded {
		w.shutdown().await?;
	}
	Ok(())
}

impl Authentication<'_> {
	/// Read and parse the sub negotiation request in the following format:
	///```not_rust
	/// +----+------+----------+------+----------+
	/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	/// +----+------+----------+------+----------+
	/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	/// +----+------+----------+------+----------+
	///```
	/// , and extract `user` and `pass`.
	async fn read<R>(reader: &mut R) -> Result<Authentication<'static>, SocksOrIoError>
	where
		R: AsyncRead + Unpin,
	{
		let ver = reader.read_u8().await?;
		// use 0x01 for authentication process
		if ver != SUB_VERS {
			return Err(Error::WrongVersion(ver).into());
		}
		// username
		let mut buf = Vec::with_capacity(128);
		read_block(reader, &mut buf).await?;
		let user = String::from_utf8(buf.clone())
			.map_err(|_e| SocksOrIoError::Socks(Error::Custom("username is not utf8".into())))?
			.into();
		// password
		read_block(reader, &mut buf).await?;
		let pass = buf.into();

		Ok(Authentication { user, pass })
	}
}

/// A list of SOCKS5 authentication methods.
struct Methods<'a>(pub Cow<'a, [u8]>);

impl<'a> Methods<'a> {
	/// Read methods in the following format:
	///```not_rust
	/// +----+----------+----------+
	/// |VER | NMETHODS | METHODS  |
	/// +----+----------+----------+
	/// | 1  |    1     | 1 to 255 |
	/// +----+----------+----------+
	///```
	async fn read<R>(reader: &mut R, buf: &'a mut Vec<u8>) -> Result<Methods<'a>, SocksOrIoError>
	where
		R: AsyncRead + Unpin,
	{
		let mut ver_n = [0_u8; 2];
		reader.read_exact(&mut ver_n).await?;
		let ver = ver_n[0];
		let n = ver_n[1];
		check_version(ver)?;

		buf.resize(n.into(), 0);
		reader.read_exact(buf).await?;

		let res = Cow::Borrowed(buf.as_slice());
		return Ok(Methods(res));
	}

	fn choose(&self, need_auth: bool) -> Option<AcceptableMethod> {
		let wanted_method = if need_auth {
			AcceptableMethod::UsernamePassword
		} else {
			AcceptableMethod::NoAuthentication
		};
		self.0.as_ref().iter().find_map(|&n| {
			if n == wanted_method as u8 {
				Some(wanted_method)
			} else {
				None
			}
		})
	}
}

/// Read a block of data in the following format
///
///```not_rust
/// +-----+----------+
/// | LEN |   DATA   |
/// +-----+----------+
/// |  1  | 1 to 255 |
/// +-----+----------+
///```
///
/// into `buf`.
/// All existing data in `buf` will be gone.
#[inline]
async fn read_block<R>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<()>
where
	R: AsyncRead + Unpin + ?Sized,
{
	let len = usize::from(reader.read_u8().await?);
	buf.resize(len, 0);
	reader.read_exact(buf).await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use std::{collections::HashMap, str::FromStr};
		use url::Url;

		let data = [
			(
				"socks5://127.0.0.1:22222",
				SettingsBuilder {
					users: HashMap::new(),
					is_udp_enabled: false,
				},
			),
			(
				"socks5://user:pass@127.0.0.1",
				SettingsBuilder {
					users: [("user", "pass")]
						.iter()
						.map(|(user, pass)| (user.to_string(), pass.to_string()))
						.collect(),
					is_udp_enabled: false,
				},
			),
		];

		for (url, expected) in data {
			let url = Url::from_str(url).unwrap();
			let output = SettingsBuilder::parse_url(&url).unwrap();
			assert_eq!(expected, output);
		}
	}

	#[test]
	fn test_display_info() {
		use crate::protocol::DisplayInfo;
		use std::collections::HashMap;

		let auth: HashMap<String, String> = [
			("alice".into(), "password".into()),
			("bob".into(), "password".into()),
		]
		.into();
		let mut s = SettingsBuilder {
			users: HashMap::new(),
			is_udp_enabled: false,
		};
		// Empty
		assert_eq!(s.brief().to_string(), "socks5-in");
		assert_eq!(s.detail().to_string(), "socks5-in");
		// Only auth
		s.users = auth.clone();
		s.is_udp_enabled = false;
		assert_eq!(s.brief().to_string(), "socks5-in(auth)");
		assert_eq!(s.detail().to_string(), "socks5-in(users:['alice','bob'])");
		// Only UDP
		s.users = HashMap::new();
		s.is_udp_enabled = true;
		assert_eq!(s.brief().to_string(), "socks5-in(udp)");
		assert_eq!(s.detail().to_string(), "socks5-in(udp)");
		// Auth and UDP
		s.users = auth.clone();
		s.is_udp_enabled = true;
		assert_eq!(s.brief().to_string(), "socks5-in(udp,auth)");
		assert_eq!(
			s.detail().to_string(),
			"socks5-in(udp,users:['alice','bob'])"
		);
	}
}
