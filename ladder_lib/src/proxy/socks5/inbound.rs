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

use super::utils::{
	auth, check_version, Authentication, CommandCode, Error, Reply, ReplyCode, Request,
	SocksOrIoError, AUTHENTICATION_SUCCESS, SUB_VERS, VER5,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::{AcceptError, AcceptResult, FinishHandshake, HandshakeError, TcpAcceptor},
		outbound::Error as OutboundError,
		AsyncReadWrite, BytesStream, GetProtocolName,
	},
	transport,
};
use std::collections::HashMap;

const HANDSHAKE_BUFFER_CAPACITY: usize = 512;
pub(super) const AUTHENTICATION_FAILURE_REPLY: u8 = 0xff;

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "use_serde", serde(deny_unknown_fields))]
pub struct SettingsBuilder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub users: HashMap<String, String>,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: transport::inbound::SettingsBuilder,
}

impl SettingsBuilder {
	/// Creates a SOCKS5 inbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		let transport = self.transport.build()?;
		Ok(Settings::new(self.users, transport))
	}
}

#[derive(Default)]
pub struct Settings {
	users: HashMap<Vec<u8>, Vec<u8>>,
	transport: transport::inbound::Settings,
}

impl Settings {
	#[inline]
	pub fn new(
		users: impl IntoIterator<Item = (String, String)>,
		transport: transport::inbound::Settings,
	) -> Self {
		let users = users
			.into_iter()
			.map(|(name, pass)| (name.into(), pass.into()))
			.collect();
		Self { users, transport }
	}

	#[inline]
	#[must_use]
	pub fn new_no_auth(transport: transport::inbound::Settings) -> Self {
		Self::new(Vec::new(), transport)
	}
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		super::PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpAcceptor for Settings {
	#[inline]
	async fn accept_tcp<'a>(
		&'a self,
		stream: BytesStream,
	) -> Result<AcceptResult<'a>, AcceptError> {
		debug!("Accepting SOCKS5 handshake.");
		let mut stream = self.transport.accept(stream).await?;
		let mut buf = Vec::with_capacity(HANDSHAKE_BUFFER_CAPACITY);

		{
			trace!("Reading SOCKS5 method");
			let methods = Methods::read(&mut stream, &mut buf).await;
			let methods = match methods {
				Ok(m) => m,
				Err(e) => return invalid_request(Box::new(stream), e),
			};

			let method = methods
				.choose(!self.users.is_empty())
				.unwrap_or(auth::NO_ACCEPTABLE);

			stream.write_all(&[VER5, method]).await?;

			// Perform authentication
			match method {
				auth::NO_AUTH => {
					// Do nothing
				}
				auth::USERNAME => {
					// Use username/password authentication
					trace!("Reading SOCKS5 authentication");
					let auth = Authentication::read(&mut stream).await;
					let auth = match auth {
						Ok(a) => a,
						Err(e) => return invalid_request(Box::new(stream), e),
					};
					let mut success = false;
					if let Some(correct_pass) = self.users.get(auth.user.as_ref()) {
						if &auth.pass == correct_pass {
							success = true;
						}
					}

					// Reply to client
					// +----+--------+
					// |VER | STATUS |
					// +----+--------+
					// | 1  |   1    |
					// +----+--------+
					let reply_code = if success {
						AUTHENTICATION_SUCCESS
					} else {
						AUTHENTICATION_FAILURE_REPLY
					};

					stream.write_all(&[SUB_VERS, reply_code]).await?;
					// Break connection if authentication failed
					if !success {
						return Err(AcceptError::new_protocol(
							Box::new(stream),
							Error::FailedAuthentication,
						));
					}
					trace!("SOCKS5 authentication completed");
				}
				_ => {
					// No usable authentication method
					return Err(AcceptError::new_protocol(
						Box::new(stream),
						Error::UnsupportedMethod(method),
					));
				}
			}
		}

		// request
		trace!("Reading SOCKS5 request");
		let request = match Request::read(&mut stream).await {
			Ok(res) => res,
			Err(e) => {
				return Err(match e {
					SocksOrIoError::Io(e) => AcceptError::Io(e),
					SocksOrIoError::Socks(e) => AcceptError::new_protocol(Box::new(stream), e),
				})
			}
		};

		let cmd = request.code;
		let cmd = if let Ok(cmd) = CommandCode::try_from(cmd) {
			cmd
		} else {
			return Err(AcceptError::new_protocol(
				Box::new(stream),
				Error::UnsupportedCommand(cmd),
			));
		};

		if cmd != CommandCode::Connect {
			// Command not supported
			// Immediately send reply and terminate connection

			let reply = Reply {
				code: ReplyCode::Succeeded as u8,
				addr: request.addr.clone(),
			};
			reply.write_to(&mut buf);
			stream.write_all(&buf).await?;
			return Err(AcceptError::new_protocol(
				Box::new(stream),
				Error::UnsupportedCommand(cmd as u8),
			));
		}
		// Send reply later

		Ok(AcceptResult::Tcp(
			Box::new(HandshakeHandle { inner: stream }),
			request.addr,
		))
	}
}

struct HandshakeHandle {
	pub inner: BytesStream,
}

#[async_trait]
impl FinishHandshake for HandshakeHandle {
	async fn finish(mut self: Box<Self>) -> Result<BytesStream, HandshakeError> {
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
	.write_to(&mut buf);
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
		let user = buf.clone().into();
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

		buf.resize(n as usize, 0);
		reader.read_exact(buf).await?;

		let res = Cow::Borrowed(buf.as_slice());
		return Ok(Methods(res));
	}

	fn choose(&self, use_auth: bool) -> Option<u8> {
		for method in self.0.as_ref() {
			let method = *method;
			if use_auth && method == auth::USERNAME {
				return Some(method);
			}
			if !use_auth && method == auth::NO_AUTH {
				return Some(method);
			}
		}
		None
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
async fn read_block<R>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<()>
where
	R: AsyncRead + Unpin + ?Sized,
{
	let len = usize::from(reader.read_u8().await?);
	buf.resize(len, 0);
	reader.read_exact(buf).await?;
	Ok(())
}

#[inline]
fn invalid_request<T>(
	stream: impl 'static + AsyncReadWrite,
	e: SocksOrIoError,
) -> Result<T, AcceptError> {
	Err(match e {
		SocksOrIoError::Io(e) => AcceptError::Io(e),
		SocksOrIoError::Socks(e) => AcceptError::new_protocol(Box::new(stream), e),
	})
}
