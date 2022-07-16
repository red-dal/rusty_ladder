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
		AcceptableMethod, Authentication, CommandCode, Reply, ReplyCode, Request, SocksOrIoError,
		AUTH_SUCCESSFUL, SUB_VERS, VAL_NO_AUTH, VAL_NO_USER_PASS, VER5,
	},
	Error, PROTOCOL_NAME,
};
#[cfg(feature = "use-udp")]
use crate::protocol::outbound::udp::{Connector, GetConnector};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpStreamConnector},
		AsyncReadWrite, BufBytesStream, GetProtocolName, ProxyContext,
	},
	proxy::socks5::utils::AUTH_FAILED,
};

const METHODS_USERNAME: &[u8] = &[
	AcceptableMethod::NoAuthentication as u8,
	AcceptableMethod::UsernamePassword as u8,
];
const METHODS_NO_AUTH: &[u8] = &[AcceptableMethod::NoAuthentication as u8];
// Both are 0xff.
const NO_ACCEPTABLE_METHOD: u8 = AUTH_FAILED;

// --------------------------------------------------------------
//                         Builder
// --------------------------------------------------------------

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(feature = "use_serde", derive(serde::Deserialize))]
pub struct SettingsBuilder {
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub user: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub pass: String,
	pub addr: SocksAddr,
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
		Ok(Settings::new(user_pass, self.addr))
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// socks5://[user:pass@]host[:port]/
	/// ```
	/// `user` and `pass` is the percent encoded username
	/// and password for proxy authentication.
	///
	/// `host` and `port` is the domain/IP and port of the proxy server.
	/// If `port` is not specified, 1080 will be used instead.
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		const DEFAULT_PORT: u16 = 1080;
		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;
		let (user, pass) = crate::utils::url::get_user_pass(url)?
			.unwrap_or_else(|| (String::new(), String::new()));
		let addr = crate::utils::url::get_socks_addr(url, Some(DEFAULT_PORT))?;

		Ok(SettingsBuilder { user, pass, addr })
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.user.is_empty() {
			write!(f, "{PROTOCOL_NAME}-out")
		} else {
			write!(f, "{PROTOCOL_NAME}-out(auth)")
		}
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let addr = &self.addr;
		let username = &self.user;
		if username.is_empty() {
			write!(f, "{PROTOCOL_NAME}-out({addr})")
		} else {
			write!(f, "{PROTOCOL_NAME}-out(user:'{username}',addr:'{addr}')")
		}
	}
}

// --------------------------------------------------------------
//                         Settings
// --------------------------------------------------------------

pub struct Settings {
	user_pass: Option<(String, String)>,
	addr: SocksAddr,
}

impl Settings {
	#[must_use]
	#[inline]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn TcpStreamConnector> {
		Some(self)
	}

	#[inline]
	#[must_use]
	pub fn new(user_pass: Option<(String, String)>, addr: SocksAddr) -> Self {
		Self { user_pass, addr }
	}

	#[inline]
	#[must_use]
	pub fn new_no_auth(addr: SocksAddr) -> Self {
		Self::new(None, addr)
	}

	async fn priv_connect<'a>(
		&'a self,
		mut stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
	) -> Result<BufBytesStream, OutboundError> {
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

		match AcceptableMethod::from_u8(method) {
			Some(AcceptableMethod::NoAuthentication) => {}
			Some(AcceptableMethod::UsernamePassword) => {
				if let Some((user, pass)) = &self.user_pass {
					let auth = Authentication {
						user: user.as_str().into(),
						pass: pass.as_bytes().into(),
					};

					buf.clear();
					auth.write_to(&mut buf);

					stream.write_all(&buf).await?;

					let auth_reply = read_auth_reply(&mut stream).await?;
					if auth_reply != AUTH_SUCCESSFUL {
						let msg = format!(
							"SOCKS5 username/password authentication failed with reply code {}",
							auth_reply
						);
						return Err(OutboundError::FailedAuthentication(msg.into()));
					}
				}
			}
			None => {
				if method == NO_ACCEPTABLE_METHOD {
					return Err(Error::Custom("server replied no acceptable method".into()).into());
				}
				return Err(OutboundError::from(Error::UnsupportedMethod(vec![method])));
			}
		}

		// send request
		trace!("Sending request for {} to server.", dst);
		let request = Request {
			code: CommandCode::Connect as u8,
			addr: dst.clone(),
		};
		buf.clear();
		request.write_into(&mut buf);
		stream.write_all(&buf).await?;
		// read reply
		let reply = Reply::read(&mut stream).await?;
		let rep_code =
			ReplyCode::try_from(reply.code).map_err(|_| Error::UnknownReplyCode(reply.code))?;
		if rep_code != ReplyCode::Succeeded {
			return Err(Error::FailedReply(rep_code).into());
		}
		Ok(BufBytesStream::from(stream))
	}
}

impl GetProtocolName for Settings {
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpStreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
		_context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		self.priv_connect(stream, dst).await
	}

	#[inline]
	fn addr(&self, _context: &dyn ProxyContext) -> Result<Option<SocksAddr>, OutboundError> {
		Ok(Some(self.addr.clone()))
	}
}

#[cfg(feature = "use-udp")]
impl GetConnector for Settings {
	fn get_udp_connector(&self) -> Option<Connector<'_>> {
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
		buf.put_slice(self.user.as_bytes());
		buf.put_u8(pass_len);
		buf.put_slice(&self.pass);
	}
}

impl AcceptableMethod {
	pub fn from_u8(n: u8) -> Option<Self> {
		match n {
			VAL_NO_AUTH => Some(Self::NoAuthentication),
			VAL_NO_USER_PASS => Some(Self::UsernamePassword),
			_ => None,
		}
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

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use std::str::FromStr;
		use url::Url;

		let data = [
			(
				"socks5://127.0.0.1:22222",
				SettingsBuilder {
					user: String::new(),
					pass: String::new(),
					addr: "127.0.0.1:22222".parse().unwrap(),
				},
			),
			(
				"socks5://user:pass@127.0.0.1",
				SettingsBuilder {
					user: "user".into(),
					pass: "pass".into(),
					addr: "127.0.0.1:1080".parse().unwrap(),
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
		let mut s = SettingsBuilder {
			user: String::new(),
			pass: String::new(),
			addr: "localhost:12345".parse().unwrap(),
		};
		assert_eq!(s.brief().to_string(), "socks5-out");
		assert_eq!(s.detail().to_string(), "socks5-out(localhost:12345)");
		// With auth
		s.user = String::from("alice");
		s.pass = String::from("alice_password");
		assert_eq!(s.brief().to_string(), "socks5-out(auth)");
		assert_eq!(
			s.detail().to_string(),
			"socks5-out(user:'alice',addr:'localhost:12345')"
		);
	}
}
