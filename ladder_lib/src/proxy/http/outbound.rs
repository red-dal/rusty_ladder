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
	utils::{encode_auth, get_version, insert_headers, put_request_head, read_http, ReadError},
	PROTOCOL_NAME,
};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, StreamConnector, StreamFunc},
		AsyncReadWrite, BufBytesStream, GetProtocolName, ProxyContext,
	},
};
use http::{header, Request, StatusCode};
use tokio::io::BufReader;

// ------------------------------------------------------------------
//                               Builder
// ------------------------------------------------------------------

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct SettingsBuilder {
	/// Use no authentication if empty.
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub user: String,
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub pass: String,
	pub addr: SocksAddr,
}

impl SettingsBuilder {
	/// Creates an HTTP outbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(Settings::new(&self.user, &self.pass, self.addr))
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// http://[user:pass@]host[:port]/
	/// ```
	/// `user` and `pass` is the percent encoded username and password
	/// for proxy authentication.
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
		let (user, pass) = crate::utils::url::get_user_pass(url)?.unwrap_or_default();
		let addr = crate::utils::url::get_socks_addr(url, Some(DEFAULT_PORT))?;
		Ok(Self { user, pass, addr })
	}
}

// ------------------------------------------------------------------
//                               Settings
// ------------------------------------------------------------------

pub struct Settings {
	auth: Option<String>,
	addr: SocksAddr,
}

impl Settings {
	#[must_use]
	#[inline]
	pub fn get_tcp_stream_connector(&self) -> Option<&dyn StreamConnector> {
		Some(self)
	}

	/// Connect to `stream` after it's connected on a transport layer.
	async fn priv_connect<'a>(
		&'a self,
		mut stream: Box<dyn AsyncReadWrite>,
		dst: &'a SocksAddr,
	) -> Result<BufBytesStream, OutboundError> {
		debug!(
			"Creating HTTP proxy connection to '{}', dst: '{}'",
			self.addr, dst
		);

		// Making HTTP request
		let dst_str = dst.to_string();
		let uri = http::Uri::builder()
			.authority(dst_str.as_str())
			.build()
			.unwrap();
		let req = {
			let mut req = Request::connect(uri)
				.header(header::HOST, &dst_str)
				.body(())
				.unwrap();

			// Add authentication is needed
			if let Some(auth) = &self.auth {
				// String like "Basic [code]" is valid, it is ok to unwrap
				let val = http::HeaderValue::from_str(&format!("Basic {}", auth))
					.expect("Cannot make header value for HTTP outbound authentication");
				req.headers_mut().insert(header::PROXY_AUTHORIZATION, val);
			}

			req
		};
		trace!("HTTP request: {:?}", req);

		let mut buf = Vec::with_capacity(512);
		// Send HTTP request to remote server
		put_request_head(&mut buf, &req);
		stream.write_all(&buf).await?;

		// Read response from remote server
		let (response, leftover) = read_response(&mut stream).await.map_err(|e| match e {
			ReadError::Io(e) => OutboundError::Io(e),
			ReadError::Protocol(e) | ReadError::BadRequest(e) => OutboundError::Protocol(e),
			ReadError::Partial => OutboundError::Protocol("incomplete HTTP response".into()),
		})?;

		trace!("Received HTTP response {:?}", response);

		let status = response.status();
		match status {
			StatusCode::OK => {
				// do nothing
			}
			StatusCode::UNAUTHORIZED => {
				let msg = format!("HTTP authentication failed with status code {}", status);
				return Err(OutboundError::FailedAuthentication(msg.into()));
			}
			StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
				return Err(OutboundError::EmptyAuthentication)
			}
			_ => {
				return Err(OutboundError::Protocol(
					format!("HTTP response status code {}", status).into(),
				))
			}
		}

		let (rh, wh) = stream.split();
		let rh = if leftover.is_empty() {
			rh
		} else {
			Box::new(AsyncReadExt::chain(std::io::Cursor::new(leftover), rh))
		};
		Ok(BufBytesStream::new(Box::new(BufReader::new(rh)), wh))
	}
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
	}
}

#[cfg(feature = "use-udp")]
impl crate::protocol::outbound::udp::GetConnector for Settings {
	fn get_udp_connector(&self) -> Option<crate::protocol::outbound::udp::Connector<'_>> {
		None
	}
}

#[async_trait]
impl StreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream_func: Box<StreamFunc<'a>>,
		dst: SocksAddr,
		context: &'a dyn ProxyContext,
	) -> Result<BufBytesStream, OutboundError> {
		let stream = stream_func(self.addr.clone(), context).await?;
		self.priv_connect(stream, &dst).await
	}
}

impl Settings {
	#[inline]
	#[must_use]
	pub fn new(user: &str, pass: &str, addr: SocksAddr) -> Self {
		let auth = if user.is_empty() && pass.is_empty() {
			None
		} else {
			Some(encode_auth(user, pass))
		};

		Self { auth, addr }
	}

	#[inline]
	#[must_use]
	pub fn new_no_auth(addr: SocksAddr) -> Self {
		Self::new("", "", addr)
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.user.is_empty() && self.pass.is_empty() {
			f.write_str("http-out")
		} else {
			f.write_str("http-out-auth")
		}
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let addr = &self.addr;
		let username = &self.user;
		if username.is_empty() {
			write!(f, "http-out({addr})")
		} else {
			write!(f, "http-out(user:'{username}',addr:'{addr}')")
		}
	}
}

async fn read_response<IO: AsyncRead + Unpin>(
	stream: &mut IO,
) -> Result<(http::Response<()>, Vec<u8>), ReadError> {
	trace!("Reading HTTP response");
	read_http(stream, parse_response).await
}

/// Try to parse bytes in `buf` as an HTTP response.
///
/// Returns an HTTP response and the number of bytes parsed if successful.
fn parse_response(buf: &[u8]) -> Result<(http::Response<()>, usize), ReadError> {
	let mut headers = [httparse::EMPTY_HEADER; 32];
	let mut parsed_resp = httparse::Response::new(&mut headers);

	let len = match parsed_resp
		.parse(buf)
		.map_err(|e| ReadError::Protocol(e.into()))?
	{
		httparse::Status::Complete(len) => len,
		httparse::Status::Partial => {
			return Err(ReadError::Partial);
			// Do nothing
		}
	};

	let ver = get_version(
		parsed_resp
			.version
			.expect("Version in HTTP response is empty."),
	)?;
	let status = parsed_resp
		.code
		.expect("Status code in response cannot be empty");

	let mut resp = http::Response::builder()
		.version(ver)
		.status(status)
		.body(())
		.map_err(|e| ReadError::BadRequest(e.into()))?;

	insert_headers(resp.headers_mut(), parsed_resp.headers)?;

	trace!("HTTP response read: {:?}", resp);
	Ok((resp, len))
}

#[cfg(test)]
mod tests {
	use super::*;
	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use super::SettingsBuilder;
		use std::str::FromStr;
		use url::Url;

		let data = [
			(
				"http://127.0.0.1:22222",
				SettingsBuilder {
					user: String::new(),
					pass: String::new(),
					addr: "127.0.0.1:22222".parse().unwrap(),
				},
			),
			(
				"http://user:pass@127.0.0.1:22222",
				SettingsBuilder {
					user: "user".into(),
					pass: "pass".into(),
					addr: "127.0.0.1:22222".parse().unwrap(),
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
	fn test_display_info_auth() {
		use crate::protocol::DisplayInfo;
		let s = SettingsBuilder {
			user: "test_user".into(),
			pass: "password".into(),
			addr: "localhost:1234".parse().unwrap(),
		};
		assert_eq!(format!("{}", s.brief()), "http-out-auth");
		assert_eq!(
			format!("{}", s.detail()),
			"http-out(user:'test_user',addr:'localhost:1234')"
		);
	}

	#[test]
	fn test_display_info_no_auth() {
		use crate::protocol::DisplayInfo;
		let s = SettingsBuilder {
			user: String::new(),
			pass: String::new(),
			addr: "localhost:1234".parse().unwrap(),
		};
		assert_eq!(format!("{}", s.brief()), "http-out");
		assert_eq!(format!("{}", s.detail()), "http-out(localhost:1234)");
	}
}
