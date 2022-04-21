use super::{SecurityType, SettingsBuilder, PROTOCOL_NAME};
use crate::{prelude::BoxStdErr, transport::outbound::Builder as TransportBuilder};
use std::str::FromStr;
use uuid::Uuid;

impl SettingsBuilder {
	/// Try to parse `url`.
	///
	/// If feature `parse-url-v2rayn` is enabled, `url` will be parsed using
	/// [v2rayn format](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))
	/// first.
	///
	/// If this failed or feature is not enabled, `url` will be parsed
	/// using [standard format](https://github.com/v2fly/v2fly-github-io/issues/26).
	///
	/// # Errors
	/// Return an error if `url` does not match the above format.
	pub fn parse_url(url: &url::Url) -> Result<(Self, TransportBuilder), BoxStdErr> {
		#[cfg(feature = "parse-url-v2rayn")]
		{
			if let Ok(result) = parse_url_v2rayn(url) {
				return Ok(result);
			}
		}
		parse_url_std(url)
	}
}

/// Parse a URL with the format stated in
/// <https://github.com/v2fly/v2fly-github-io/issues/26>
fn parse_url_std(url: &url::Url) -> Result<(SettingsBuilder, TransportBuilder), BoxStdErr> {
	use crate::transport;

	#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
	fn make_ws_builder(url: &url::Url) -> transport::ws::OutboundBuilder {
		let mut path = None;
		let mut host = None;
		for (key, value) in url.query_pairs() {
			if key == "path" {
				path = Some(value);
			} else if key == "host" {
				host = Some(value);
			}
		}
		transport::ws::OutboundBuilder {
			headers: Default::default(),
			path: path.map_or_else(String::new, Into::into),
			host: host.map_or_else(String::new, Into::into),
			tls: None,
		}
	}

	let addr = crate::utils::url::get_socks_addr(url, None)?;

	crate::utils::url::check_scheme(url, PROTOCOL_NAME)?;
	let transport_str = url.username();
	let transport: transport::outbound::Builder = match transport_str {
		"tcp" => transport::outbound::Builder::default(),
		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		"tls" => transport::tls::OutboundBuilder::default().into(),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		"ws" => make_ws_builder(url).into(),
		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		"ws+tls" => {
			let mut builder = make_ws_builder(url);
			builder.tls = Some(transport::tls::OutboundBuilder::default());
			builder.into()
		}
		_ => return Err(format!("invalid transport string '{}'", transport_str).into()),
	};
	let uuid_authid = url.password().ok_or("VMess URL missing UUID")?;
	let (id_str, auth_id_num) = if uuid_authid.len() <= 36 {
		// UUID only
		(uuid_authid, 0)
	} else {
		let (id_str, auth_id_str) = uuid_authid.split_at(36);
		// Skip the first character '-'
		let auth_id_str = auth_id_str
			.strip_prefix('-')
			.ok_or_else(|| format!("invalid auth id format '{}'", auth_id_str))?;

		let auth_id_num = usize::from_str(auth_id_str)
			.map_err(|_| format!("cannot parse '{}' into usize", auth_id_str))?;
		(id_str, auth_id_num)
	};
	let id = Uuid::from_str(id_str).map_err(|e| format!("invalid UUID '{}' ({})", id_str, e))?;

	if auth_id_num > 0 {
		return Err("cannot use authid other than 0, only AEAD header is supported".into());
	}

	Ok((
		SettingsBuilder {
			addr,
			id,
			sec: SecurityType::Auto,
			use_legacy_header: false,
		},
		transport,
	))
}

#[cfg(feature = "parse-url-v2rayn")]
/// Parse `url` using
/// [v2ray format](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))
/// .
fn parse_url_v2rayn(url: &url::Url) -> Result<(SettingsBuilder, TransportBuilder), BoxStdErr> {
	todo!()
}

#[cfg(test)]
mod tests {
	use super::{SecurityType, SettingsBuilder};
	use crate::transport;
	use std::str::FromStr;
	use url::Url;
	#[test]
	fn test_parse_url() {
		let data = [
			(
				"vmess://tcp:2e09f64c-c967-4ce3-9498-fdcd8e39e04e-0@google.com:4433/?query=Value1#Connection2",
				(SettingsBuilder {
					addr: "google.com:4433".parse().unwrap(),
					id: "2e09f64c-c967-4ce3-9498-fdcd8e39e04e".parse().unwrap(),
					sec: SecurityType::Auto,
					use_legacy_header: false,
				}, Default::default()),
			),
			(
				"vmess://ws+tls:7db04e8f-7cfc-46e0-9e18-d329c22ec353-0@myServer.com:12345/?path=%2FmyServerAddressPath%2F%E4%B8%AD%E6%96%87%E8%B7%AF%E5%BE%84%2F&host=www.myServer.com",
				(
					SettingsBuilder {
						addr: "myServer.com:12345".parse().unwrap(),
						id: "7db04e8f-7cfc-46e0-9e18-d329c22ec353".parse().unwrap(),
						sec: SecurityType::Auto,
						use_legacy_header: false,
					},
					transport::outbound::Builder::Ws(transport::ws::OutboundBuilder {
						headers: Default::default(),
						path: "/myServerAddressPath/中文路径/".into(),
						host: "www.myServer.com".into(),
						tls: Some(transport::tls::OutboundBuilder {
							alpns: Vec::new(),
							ca_file: None,
						}),
					}),
				),
			),
		];
		for (url, expected) in data {
			let url = Url::from_str(url).unwrap();
			let output = SettingsBuilder::parse_url(&url).unwrap();
			assert_eq!(expected, output);
		}
	}
}
