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
		auth, Authentication, CommandCode, Reply, ReplyCode, Request, SocksOrIoError,
		AUTHENTICATION_SUCCESS, SUB_VERS, VER5,
	},
	Error,
};
use crate::{
	prelude::*,
	protocol::{
		GetConnector, GetProtocolName, OutboundError, ProxyContext, ProxyStream, TcpConnector,
		TcpStreamConnector, UdpConnector,
	},
	transport,
};

const METHODS_USERNAME: &[u8] = &[auth::NO_AUTH, auth::USERNAME];
const METHODS_NO_AUTH: &[u8] = &[auth::NO_AUTH];

#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub user: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub pass: String,
	pub addr: SocksAddr,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: transport::outbound::SettingsBuilder,
}

impl SettingsBuilder {
	/// Creates a SOCKS5 outbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		let user_pass = if self.user.is_empty() && self.pass.is_empty() {
			None
		} else {
			Some((self.user, self.pass))
		};
		Ok(Settings::new(user_pass, self.addr, self.transport.build()?))
	}
}

pub struct Settings {
	user_pass: Option<(String, String)>,
	addr: SocksAddr,
	transport: transport::outbound::Settings,
}

impl Settings {
	#[inline]
	#[must_use]
	pub fn new(
		user_pass: Option<(String, String)>,
		addr: SocksAddr,
		transport: transport::outbound::Settings,
	) -> Self {
		Self {
			user_pass,
			addr,
			transport,
		}
	}

	#[inline]
	#[must_use]
	pub fn new_no_auth(addr: SocksAddr, transport: transport::outbound::Settings) -> Self {
		Self::new(None, addr, transport)
	}

	async fn priv_connect<'a>(
		&'a self,
		mut stream: ProxyStream,
		dst: &'a SocksAddr,
	) -> Result<ProxyStream, OutboundError> {
		debug!(
			"Creating SOCKS5 connection to '{}', dst: '{}'",
			&self.addr, dst
		);

		let mut buf = Vec::with_capacity(512);

		let methods = if self.user_pass.is_some() {
			METHODS_USERNAME
		} else {
			METHODS_NO_AUTH
		};

		write_methods_to(methods, &mut buf);
		stream.write_all(&buf).await?;

		let method = {
			let (ver, method) = {
				let mut buf = [0_u8; 2];
				stream.read_exact(&mut buf[..2]).await?;
				(buf[0], buf[1])
			};

			if ver != VER5 {
				return Err(Error::WrongVersion(ver).into());
			}
			method
		};
		trace!("Server asked for authentication with method {}", method);

		match method {
			auth::NO_AUTH => {
				// do nothing
			}
			auth::USERNAME => {
				// Send username

				if let Some((user, pass)) = &self.user_pass {
					let auth = Authentication {
						user: user.as_bytes().into(),
						pass: pass.as_bytes().into(),
					};

					buf.clear();
					auth.write_to(&mut buf);

					stream.write_all(&buf).await?;

					let auth_reply = read_auth_reply(&mut stream).await?;
					if auth_reply != AUTHENTICATION_SUCCESS {
						let msg = format!(
							"SOCKS5 username/password authentication failed with reply code {}",
							auth_reply
						);
						return Err(OutboundError::FailedAuthentication(msg.into()));
					}
				}
			}
			_ => {
				return Err(OutboundError::from(Error::UnsupportedMethod(method)));
			}
		};

		// send request
		trace!("Sending request for {} to server.", dst);
		let request = Request {
			code: CommandCode::Connect as u8,
			addr: dst.clone(),
		};
		request.write_to(&mut buf);
		stream.write_all(&buf).await?;
		// read reply
		let reply = Reply::read(&mut stream).await?;
		let rep_code =
			ReplyCode::try_from(reply.code).map_err(|_| Error::UnknownReplyCode(reply.code))?;
		if rep_code != ReplyCode::Succeeded {
			return Err(Error::FailedReply(rep_code).into());
		}
		Ok(stream)
	}
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		super::PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpStreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream: ProxyStream,
		dst: &'a SocksAddr,
		_context: &'a dyn ProxyContext,
	) -> Result<ProxyStream, OutboundError> {
		let stream = self.transport.connect_stream(stream, &self.addr).await?;
		self.priv_connect(stream, dst).await
	}

	#[inline]
	fn addr(&self) -> &SocksAddr {
		&self.addr
	}
}

#[async_trait]
impl TcpConnector for Settings {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<ProxyStream, OutboundError> {
		let stream = self.transport.connect(&self.addr, context).await?;
		self.priv_connect(stream, dst).await
	}
}

impl GetConnector for Settings {
	fn get_udp_connector(&self) -> Option<UdpConnector<'_>> {
		None
	}
}

impl Authentication<'_> {
	/// Write the authentication into `buf` in the following format:
	///```not_rust
	/// +----+------+----------+------+----------+
	/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	/// +----+------+----------+------+----------+
	/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	/// +----+------+----------+------+----------+
	///```
	/// Beware that all existing data in `dst` will be wiped.
	#[allow(clippy::cast_possible_truncation)]
	pub fn write_to(&self, buf: &mut impl BufMut) {
		// The length of `user` and `pass` is at most 255, ok to convert.
		let user_len = self.user.len() as u8;
		let pass_len = self.pass.len() as u8;
		buf.put_u8(SUB_VERS);
		buf.put_u8(user_len);
		buf.put_slice(&self.user);
		buf.put_u8(pass_len);
		buf.put_slice(&self.pass);
	}
}

/// Write methods into `buf` in the following format:
///```not_rust
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 1  |    1     | 1 to 255 |
/// +----+----------+----------+
///```
fn write_methods_to(methods: &[u8], buf: &mut impl BufMut) {
	// The length of `methods` can only be 1 or 2,
	// so it is ok to be directly converted into u8.
	#[allow(clippy::cast_possible_truncation)]
	let len = methods.len() as u8;
	buf.put_slice(&[VER5, len]);
	buf.put_slice(methods);
}

async fn read_auth_reply<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u8, SocksOrIoError> {
	let mut tmp_buf = [0_u8; 2];
	reader.read_exact(&mut tmp_buf).await?;
	let ver = tmp_buf[0];
	let status = tmp_buf[1];

	if ver != SUB_VERS {
		return Err(Error::WrongVersion(ver).into());
	}

	Ok(status)
}
