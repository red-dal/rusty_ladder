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
	encode_auth, get_version, insert_headers, put_request_head, read_http, ReadError,
};
use crate::{
	prelude::*,
	protocol::{
		outbound::{Error as OutboundError, TcpConnector, TcpStreamConnector},
		BytesStream, GetProtocolName, ProxyContext,
	},
	transport,
	utils::BufferedReadHalf,
};
use http::{header, Request, StatusCode};

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
	#[cfg_attr(feature = "use_serde", serde(default))]
	pub transport: transport::outbound::SettingsBuilder,
}

impl SettingsBuilder {
	/// Creates an HTTP outbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		Ok(Settings::new(
			&self.user,
			&self.pass,
			self.addr,
			self.transport.build()?,
		))
	}
}

pub struct Settings {
	auth: Option<String>,
	addr: SocksAddr,
	transport: transport::outbound::Settings,
}

impl Settings {
	/// Connect to `stream` after it's connected on a transport layer.
	async fn priv_connect<'a>(
		&'a self,
		mut stream: BytesStream,
		dst: &'a SocksAddr,
	) -> Result<BytesStream, OutboundError> {
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

		let rh = BufferedReadHalf::new(stream.r, leftover);
		Ok(BytesStream::new(Box::new(rh), stream.w))
	}
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		super::PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpConnector for Settings {
	async fn connect(
		&self,
		dst: &SocksAddr,
		context: &dyn ProxyContext,
	) -> Result<BytesStream, OutboundError> {
		let stream = self.transport.connect(&self.addr, context).await?;
		Ok(self.priv_connect(stream, dst).await?)
	}
}

#[cfg(feature = "use-udp")]
impl crate::protocol::outbound::udp::GetConnector for Settings {
	fn get_udp_connector(&self) -> Option<crate::protocol::outbound::udp::Connector<'_>> {
		None
	}
}

#[async_trait]
impl TcpStreamConnector for Settings {
	async fn connect_stream<'a>(
		&'a self,
		stream: BytesStream,
		dst: &'a SocksAddr,
		_context: &'a dyn ProxyContext,
	) -> Result<BytesStream, OutboundError> {
		let stream = self.transport.connect_stream(stream, &self.addr).await?;
		Ok(self.priv_connect(stream, dst).await?)
	}

	#[inline]
	fn addr(&self) -> &SocksAddr {
		&self.addr
	}
}

impl Settings {
	#[inline]
	#[must_use]
	pub fn new(
		user: &str,
		pass: &str,
		addr: SocksAddr,
		transport: transport::outbound::Settings,
	) -> Self {
		let auth = if user.is_empty() && pass.is_empty() {
			None
		} else {
			Some(encode_auth(user, pass))
		};

		Self {
			auth,
			addr,
			transport,
		}
	}

	#[inline]
	#[must_use]
	pub fn new_no_auth(addr: SocksAddr, transport: transport::outbound::Settings) -> Self {
		Self::new("", "", addr, transport)
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
