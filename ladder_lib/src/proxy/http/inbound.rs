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
		encode_auth, get_version, insert_headers, put_http_headers, put_request_head, read_http,
		ReadError,
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
use http::{header, uri::Scheme, Method, StatusCode, Uri};
use std::{
	collections::{HashMap, HashSet},
	io,
};

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
			.map(|(name, pass)| (name.as_str(), pass.as_str()));
		Ok(Settings::new(users))
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

pub struct Settings {
	auths: HashSet<String>,
}

impl Settings {
	#[inline]
	pub fn new<'a>(users: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
		let auths = users
			.into_iter()
			.map(|(user, pass)| encode_auth(user, pass))
			.collect();
		Self { auths }
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
		mut stream: Box<dyn AsyncReadWrite>,
		_info: SessionInfo,
	) -> Result<AcceptResult<'a>, AcceptError> {
		let (mut req, leftover) = match read_request(&mut stream).await {
			Ok(r) => r,
			Err(ReadError::Io(e)) => return Err(AcceptError::Io(e)),
			Err(ReadError::BadRequest(e)) => {
				return write_err_response(&mut stream, StatusCode::BAD_REQUEST, e).await;
			}
			Err(ReadError::Protocol(e)) => return Err(AcceptError::new_silent_drop(stream, e)),
			Err(ReadError::Partial) => {
				debug!("Only partial HTTP request is read.");
				return Err(AcceptError::Io(io::Error::new(
					io::ErrorKind::InvalidData,
					ReadError::Partial,
				)));
			}
		};

		if let Err((e, status)) = check_update_auth(&mut req, &self.auths) {
			debug!(
				"HTTP authentication failed with error ({}) and status code {}",
				e, status
			);
			return write_err_response(&mut stream, status, e).await;
		}

		let dst = match url_to_addr(req.uri()) {
			Ok(addr) => addr,
			Err(e) => {
				debug!("Cannot convert uri '{}' into SocksAddr", req.uri());
				return write_err_response(&mut stream, StatusCode::BAD_REQUEST, e).await;
			}
		};

		if req.method() == Method::CONNECT {
			// On connect method,
			// do nothing.
		} else {
			// On any other method,
			// remove all proxy related headers.
			let headers = req.headers_mut();
			if let Some(val) = headers.remove("proxy-connection") {
				headers.insert(header::CONNECTION, val);
			}
		}

		let handshake = HandshakeFinisher::new(stream, req, leftover);
		Ok(AcceptResult::Tcp(Box::new(handshake), dst))
	}
}

async fn write_err_response<T, W: AsyncWrite + Unpin>(
	w: &mut W,
	status: StatusCode,
	e: BoxStdErr,
) -> Result<T, AcceptError> {
	write_simple_response(w, status).await?;
	w.shutdown().await?;
	Err(AcceptError::Io(io::Error::new(io::ErrorKind::Other, e)))
}

struct HandshakeFinisher {
	stream: Box<dyn AsyncReadWrite>,
	req: http::Request<()>,
	leftover: Vec<u8>,
}

impl HandshakeFinisher {
	fn new(stream: Box<dyn AsyncReadWrite>, req: http::Request<()>, leftover: Vec<u8>) -> Self {
		Self {
			stream,
			req,
			leftover,
		}
	}
}

#[async_trait]
impl FinishHandshake for HandshakeFinisher {
	async fn finish(mut self: Box<Self>) -> Result<BufBytesStream, HandshakeError> {
		let mut sent_buf = Vec::new();
		let mut client_stream = self.stream;
		let request = self.req;

		if request.method() == Method::CONNECT {
			// For connect method,
			// get a status code to send back to client.
			trace!("HTTP inbound using CONNECT method");
			write_simple_response(&mut client_stream, StatusCode::OK).await?;
		} else {
			// For methods other than connect,
			// put request into buffer and send to server.

			// Break down request
			let (mut req_parts, _) = request.into_parts();
			let uri_parts = req_parts.uri.into_parts();

			// New url only keep query path
			let mut new_uri_parts = http::uri::Parts::default();
			new_uri_parts.path_and_query = uri_parts.path_and_query;
			let new_uri =
				Uri::from_parts(new_uri_parts).expect("Cannot make new HTTP URI from parts");
			req_parts.uri = new_uri;

			// Reform request
			let req = http::Request::from_parts(req_parts, ());

			trace!("HTTP inbound not using CONNECT method ({})", req.method());
			put_request_head(&mut sent_buf, &req);
			if let Ok(buf) = std::str::from_utf8(&sent_buf) {
				trace!("HTTP inbound buffer: {}", buf);
			}
		}

		// Put leftover bytes into buffer to send to server
		sent_buf.extend(&self.leftover);

		let (r, w) = client_stream.split();
		let r = Box::new(AsyncReadExt::chain(io::Cursor::new(sent_buf), r));

		Ok(BufBytesStream::from_raw(r, w))
	}

	async fn finish_err(self: Box<Self>, err: &OutboundError) -> Result<(), HandshakeError> {
		let mut client_stream = self.stream;
		let status = if err.is_timeout() {
			StatusCode::GATEWAY_TIMEOUT
		} else {
			StatusCode::BAD_GATEWAY
		};
		debug!("Outbound error occurred when finishing HTTP inbound handshake. Sending response with status code {}", status);
		write_simple_response(&mut client_stream, status).await?;
		client_stream.shutdown().await?;
		Ok(())
	}
}

/// Returns the authentication result and the status code.
///
/// # Error
/// If authentication failed, an `Err` and a status code other than 200 will be returned.
fn check_update_auth(
	req: &mut http::Request<()>,
	auths: &HashSet<String>,
) -> Result<(), (BoxStdErr, StatusCode)> {
	if !auths.is_empty() {
		if let Some(auth) = req.headers().get(header::PROXY_AUTHORIZATION) {
			if let Ok(auth_str) = auth.to_str() {
				// Check auth format
				let mut parts = auth_str.split(' ');
				let auth_type = if let Some(auth_type) = parts.next() {
					auth_type
				} else {
					let msg = format!("wrong HTTP authentication format '{}'", auth_str);
					return Err((msg.into(), StatusCode::UNAUTHORIZED));
				};
				let auth_code = if let Some(auth_code) = parts.next() {
					auth_code
				} else {
					let msg = format!("wrong HTTP authentication format '{}'", auth_str);
					return Err((msg.into(), StatusCode::UNAUTHORIZED));
				};

				// Authentication value must be ascii
				if !auth_type.eq_ignore_ascii_case("basic") {
					let msg = format!(
						"wrong HTTP authentication type '{}', only 'Basic' is supported",
						auth_type
					);
					return Err((msg.into(), StatusCode::UNAUTHORIZED));
				}

				if auths.contains(auth_code) {
					// Authentication succeeded, remove auth header.
					req.headers_mut().remove(header::PROXY_AUTHORIZATION);
				} else {
					// Authentication failed
					let msg = format!("HTTP authentication failed with auth '{}'", auth_str);
					return Err((msg.into(), StatusCode::UNAUTHORIZED));
				}
			} else {
				// Authentication not valid UTF8
				let msg = "HTTP authentication is not valid UTF8";
				return Err((msg.into(), StatusCode::UNAUTHORIZED));
			}
		} else {
			// Authentication required, but request has none
			let msg = "HTTP authentcation is required, but none provided";
			return Err((msg.into(), StatusCode::PROXY_AUTHENTICATION_REQUIRED));
		}
	}
	Ok(())
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

async fn write_simple_response<W: AsyncWrite + Unpin>(
	w: &mut W,
	status: StatusCode,
) -> io::Result<()> {
	let mut buf = Vec::with_capacity(512);
	let response = http::Response::builder()
		.status(status)
		.body(())
		.expect("Cannot build HTTP response with status code");
	put_response(&mut buf, &response);
	w.write_all(&buf).await
}

fn put_response<B: BufMut>(buf: &mut B, response: &http::Response<()>) {
	// Line 0
	// Version
	buf.put_slice(b"HTTP/1.1 ");
	// Status code
	buf.put_slice(response.status().as_str().as_bytes());
	buf.put_slice(b" ");
	// Reason, optional
	if let Some(reason) = response.status().canonical_reason() {
		buf.put_slice(reason.as_bytes());
	}
	// End of line 0
	buf.put_slice(CRLF);

	// Multiple lines for response headers
	put_http_headers(buf, response.headers());

	// End of response
	buf.put_slice(CRLF);
}

async fn read_request<IO>(stream: &mut IO) -> Result<(http::Request<()>, Vec<u8>), ReadError>
where
	IO: AsyncRead + Unpin,
{
	trace!("Reading HTTP request");
	read_http(stream, parse_request).await
}

/// Try to parse bytes in `buf` as an HTTP request.
///
/// Returns an HTTP request and the number of bytes parsed if successful.
fn parse_request(buf: &[u8]) -> Result<(http::Request<()>, usize), ReadError> {
	let mut headers = [httparse::EMPTY_HEADER; 32];
	let mut parsed_req = httparse::Request::new(&mut headers);

	let len = match parsed_req
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

	trace!("HTTP request read: {:?}", req);
	Ok((req, len))
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "parse-url")]
	#[test]
	fn test_parse_url() {
		use super::SettingsBuilder;
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
}
