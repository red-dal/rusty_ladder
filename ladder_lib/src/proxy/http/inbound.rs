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
		encode_auth, get_version, insert_headers, put_http_headers, put_request_head, ReadError,
	},
	MAX_USERNAME_SIZE, PROTOCOL_NAME,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::{AcceptError, Finish, Handshake, HandshakeError, SessionInfo, StreamAcceptor},
		outbound::Error as OutboundError,
		AsyncReadWrite, BufBytesStream, GetProtocolName,
	},
	proxy::http::MAX_BUFFER_SIZE,
	utils::ChainedReadHalf,
};
use http::{header, uri::Scheme, Method, StatusCode, Uri};
use std::{
	collections::{HashMap, HashSet},
	io,
};
use tokio::io::{AsyncBufRead, BufReader};

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
	// A list of (username, password)
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub users: HashMap<String, String>,
}

impl SettingsBuilder {
	/// Creates a HTTP inbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		let users = self
			.users
			.iter()
			.map(|(user, pass)| (user.as_str(), pass.as_str()));
		Settings::new(users)
	}

	/// Parse a URL with the following format:
	/// ```plain
	/// http://[user:pass@]bind_addr:bind_port/
	/// ```
	/// `user` and `pass` is the percent encoding username and password
	/// for proxy authentication.
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	#[cfg(feature = "parse-url")]
	pub fn parse_url(url: &url::Url) -> Result<Self, BoxStdErr> {
		crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
		crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;
		let users = crate::utils::url::get_user_pass(url)?.into_iter().collect();
		crate::utils::url::check_empty_path(url, PROTOCOL_NAME)?;
		Ok(SettingsBuilder { users })
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.users.is_empty() {
			f.write_str("http-in")
		} else {
			f.write_str("http-in-auth")
		}
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.users.is_empty() {
			// With authentication:
			f.write_str("http-in")
		} else {
			// With authentication:
			// http-in('alice','bob',...)
			f.write_str("http-in(")?;
			let mut sorted_names: Vec<&str> = self
				.users
				.iter()
				.map(|(user, _pass)| user.as_str())
				.collect();
			sorted_names.sort_unstable();
			crate::utils::fmt_iter(f, sorted_names.iter())?;
			f.write_str(")")
		}
	}
}

// ------------------------------------------------------------------
//                               Settings
// ------------------------------------------------------------------

pub struct Settings {
	auths: HashSet<String>,
}

impl Settings {
	/// Creates a new [`Settings`].
	///
	/// - `users` a list of (username, password)
	///
	/// # Errors
	///
	/// Return an error if any username and
	/// password in `users` is longer than 128 bytes.
	#[inline]
	pub fn new<'a>(users: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<Self, BoxStdErr> {
		let mut auths = HashSet::new();
		for (user, pass) in users {
			if user.len() > MAX_USERNAME_SIZE {
				return Err("username too long".into());
			}
			if pass.len() > MAX_USERNAME_SIZE {
				return Err("password too long".into());
			}
			auths.insert(encode_auth(user, pass));
		}
		Ok(Self { auths })
	}
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		PROTOCOL_NAME
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
		let (r, w) = stream.split();
		let mut r = BufReader::new(r);
		let mut wh = HttpWriteHelper::new(w);

		let req = match read_request(&mut r).await {
			Ok(r) => r,
			Err(ReadError::Io(e)) => return Err(AcceptError::Io(e)),
			Err(ReadError::BadRequest(e) | ReadError::Protocol(e)) => {
				return wh.write_response_err(StatusCode::BAD_REQUEST, e).await;
			}
			Err(ReadError::Partial) => {
				debug!("Only partial HTTP request is read.");
				return Err(AcceptError::Io(io::Error::new(
					io::ErrorKind::InvalidData,
					ReadError::Partial,
				)));
			}
		};
		match check_auth(&req, &self.auths) {
			StatusCode::OK => {
				// Do nothing
			}
			StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
				debug!("Responding to client and wait for proper authentication...");
				wh.write_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
					.await?;
				wh.w.shutdown().await?;
				return Err(AcceptError::Protocol("HTTP authentication failed".into()));
			}
			other => {
				return wh
					.write_response_err(
						other,
						format!("HTTP authentication failed (status code {})", other),
					)
					.await;
			}
		}

		let dst = match url_to_addr(req.uri()) {
			Ok(addr) => addr,
			Err(e) => {
				debug!("Cannot convert uri '{}' into SocksAddr", req.uri());
				return wh.write_response_err(StatusCode::BAD_REQUEST, e).await;
			}
		};

		let req = {
			let mut req = req;
			let headers = req.headers_mut();
			headers.remove(header::PROXY_AUTHORIZATION);
			if let Some(val) = headers.remove("proxy-connection") {
				headers.insert(header::CONNECTION, val);
			}
			req
		};

		// It's possible that outbound fails,
		// so response to client in `finish`.
		let handshake = HttpHandshake {
			stream: BufBytesStream {
				r: Box::new(r),
				w: wh.w,
			},
			req,
		};
		Ok(Handshake::Stream(Box::new(handshake), dst))
	}
}

struct HttpWriteHelper<W: AsyncWrite + Unpin> {
	pub w: W,
	// 512 bytes should be enough for writing simple responses.
	buf: [u8; 512],
}

impl<W: AsyncWrite + Unpin> HttpWriteHelper<W> {
	fn new(w: W) -> Self {
		Self { w, buf: [0u8; 512] }
	}

	fn put_response(buf: &mut impl BufMut, response: &http::Response<()>) -> usize {
		let original_remaining = buf.remaining_mut();
		// Line 0
		buf.put_slice(b"HTTP/1.1 ");
		buf.put_slice(response.status().as_str().as_bytes());
		buf.put_slice(b" ");
		if let Some(reason) = response.status().canonical_reason() {
			buf.put_slice(reason.as_bytes());
		}
		// End of line 0
		buf.put_slice(CRLF);

		put_http_headers(buf, response.headers());

		// End of response
		buf.put_slice(CRLF);
		original_remaining - buf.remaining_mut()
	}

	async fn write_response(&mut self, status: StatusCode) -> io::Result<()> {
		let mut builder = http::Response::builder().status(status);
		if StatusCode::PROXY_AUTHENTICATION_REQUIRED == status {
			builder = builder.header(http::header::PROXY_AUTHENTICATE, "Basic realm=\"proxy\"");
		}
		let response = builder
			.body(())
			.expect("Cannot build HTTP response with status code");
		let len = Self::put_response(&mut self.buf.as_mut(), &response);
		debug!("Writing HTTP response: {response:?}");
		self.w.write_all(&self.buf[..len]).await?;
		self.w.flush().await
	}

	async fn write_response_err<T>(
		mut self,
		status: StatusCode,
		e: impl Into<BoxStdErr>,
	) -> Result<T, AcceptError> {
		self.write_response(status).await?;
		self.w.shutdown().await?;
		Err(AcceptError::Io(io::Error::new(
			io::ErrorKind::Other,
			e.into(),
		)))
	}
}

struct HttpHandshake {
	stream: BufBytesStream,
	req: http::Request<()>,
}

#[async_trait]
impl Finish for HttpHandshake {
	async fn finish(mut self: Box<Self>) -> Result<BufBytesStream, HandshakeError> {
		let mut client_stream = self.stream;
		let req = self.req;

		if req.method() == Method::CONNECT {
			// Send status back to client
			trace!("HTTP inbound using CONNECT method");
			HttpWriteHelper::new(&mut client_stream)
				.write_response(StatusCode::OK)
				.await?;
			Ok(client_stream)
		} else {
			trace!("HTTP inbound not using CONNECT method ({})", req.method());
			// For non-CONNECT method, the request is proxied to dst.
			// Write the request into `sent_buf` and chain it before stream's read half.
			let mut sent_buf = Vec::new();

			let (mut req_parts, _) = req.into_parts();
			let uri_parts = req_parts.uri.into_parts();

			// New url only keep query path
			let mut new_uri_parts = http::uri::Parts::default();
			new_uri_parts.path_and_query = uri_parts.path_and_query;
			let new_uri =
				Uri::from_parts(new_uri_parts).expect("Cannot make new HTTP URI from parts");
			req_parts.uri = new_uri;

			let req = http::Request::from_parts(req_parts, ());

			put_request_head(&mut sent_buf, &req);
			if let Ok(buf) = std::str::from_utf8(&sent_buf) {
				trace!("HTTP inbound buffer: {}", buf);
			}

			Ok(BufBytesStream {
				r: Box::new(ChainedReadHalf::new(client_stream.r, sent_buf)),
				w: client_stream.w,
			})
		}
	}

	async fn finish_err(self: Box<Self>, err: &OutboundError) -> Result<(), HandshakeError> {
		let mut client_stream = self.stream;
		let status = if err.is_timeout() {
			StatusCode::GATEWAY_TIMEOUT
		} else {
			StatusCode::BAD_GATEWAY
		};
		debug!("Outbound error occurred when finishing HTTP inbound handshake. Sending response with status code {}", status);
		HttpWriteHelper::new(&mut client_stream)
			.write_response(status)
			.await?;
		client_stream.shutdown().await?;
		Ok(())
	}
}

/// Returns the authentication result and the status code.
///
/// # Error
/// If authentication failed, an `Err` and a status code other than 200 will be returned.
fn check_auth(req: &http::Request<()>, auths: &HashSet<String>) -> StatusCode {
	if !auths.is_empty() {
		if let Some(auth) = req.headers().get(header::PROXY_AUTHORIZATION) {
			if let Ok(auth_str) = auth.to_str() {
				// Check auth format
				let mut parts = auth_str.split(' ');
				let auth_type = if let Some(auth_type) = parts.next() {
					auth_type
				} else {
					debug!("wrong HTTP authentication format '{}'", auth_str);
					return StatusCode::NOT_FOUND;
				};
				let auth_code = if let Some(auth_code) = parts.next() {
					auth_code
				} else {
					debug!("wrong HTTP authentication format '{}'", auth_str);
					return StatusCode::NOT_FOUND;
				};

				// Authentication value must be ascii
				if !auth_type.eq_ignore_ascii_case("basic") {
					debug!(
						"wrong HTTP authentication type '{}', only 'Basic' is supported",
						auth_type
					);
					return StatusCode::NOT_FOUND;
				}

				if !auths.contains(auth_code) {
					debug!("HTTP authentication failed with auth '{}'", auth_str);
					return StatusCode::NOT_FOUND;
				}
			} else {
				debug!("HTTP authentication is not valid UTF8");
				return StatusCode::BAD_REQUEST;
			}
		} else {
			// Authentication required, but request has none
			debug!("HTTP authentcation is required, but none provided");
			return StatusCode::PROXY_AUTHENTICATION_REQUIRED;
		}
	}
	StatusCode::OK
}

fn url_to_addr(url: &Uri) -> Result<SocksAddr, BoxStdErr> {
	let host = url
		.host()
		.ok_or_else(|| format!("URL '{}' have no host", url))?;

	let port = if let Some(port) = url.port_u16() {
		port
	} else if let Some(scheme) = url.scheme() {
		if scheme == &Scheme::HTTP {
			80
		} else if scheme == &Scheme::HTTPS {
			443
		} else {
			return Err(format!(
				"cannot determine port from unknown scheme '{}' of URL '{}'",
				scheme, url
			)
			.into());
		}
	} else {
		return Err(format!("cannot determine port of URL '{}'", url).into());
	};

	let dest = SocksDestination::from_str(host)?;
	Ok(SocksAddr::new(dest, port))
}

async fn read_request(r: impl AsyncBufRead + Unpin) -> Result<http::Request<()>, ReadError> {
	trace!("Reading HTTP request");
	let mut buf = [0u8; MAX_BUFFER_SIZE];
	let buf = crate::utils::read_until(r, CRLF_2, &mut buf)
		.await?
		.ok_or(ReadError::Partial)?;

	let mut headers = [httparse::EMPTY_HEADER; super::utils::MAX_HEADERS_NUM];
	let mut parsed_req = httparse::Request::new(&mut headers);

	let _len = match parsed_req
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
		parsed_req
			.version
			.expect("Version in HTTP request cannot be empty."),
	)?;
	let method = parsed_req
		.method
		.expect("Method in response cannot be empty.");
	let uri = Uri::from_str(parsed_req.path.expect("Path in response cannot be empty"))
		.map_err(|e| ReadError::BadRequest(e.into()))?;

	let mut req = http::Request::builder()
		.method(method)
		.uri(uri)
		.version(ver)
		.body(())
		.map_err(|e| ReadError::BadRequest(e.into()))?;

	insert_headers(req.headers_mut(), parsed_req.headers)?;

	trace!("HTTP request: {:?}", req);
	Ok(req)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::protocol::DisplayInfo;

	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use std::{collections::HashMap, str::FromStr};
		use url::Url;

		let data = [
			(
				"http://127.0.0.1:22222",
				SettingsBuilder {
					users: HashMap::new(),
				},
			),
			(
				"http://user:pass@127.0.0.1",
				SettingsBuilder {
					users: [("user", "pass")]
						.iter()
						.map(|(user, pass)| (user.to_string(), pass.to_string()))
						.collect(),
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
	fn test_display_info_no_auth() {
		let s = SettingsBuilder {
			users: HashMap::new(),
		};
		assert_eq!(format!("{}", s.brief()), "http-in");
		assert_eq!(format!("{}", s.detail()), "http-in");
	}

	#[test]
	fn test_display_info_auth() {
		let s = SettingsBuilder {
			users: [
				("test_user".into(), "test_password".into()),
				("user2".into(), "test".into()),
			]
			.into(),
		};
		assert_eq!(format!("{}", s.brief()), "http-in-auth");
		assert_eq!(format!("{}", s.detail()), "http-in('test_user','user2')");
	}
}
