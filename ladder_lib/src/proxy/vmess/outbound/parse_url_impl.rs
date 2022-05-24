use super::{SecurityTypeBuilder, SettingsBuilder, PROTOCOL_NAME};
use crate::{
	prelude::{BoxStdErr, Tag},
	transport::outbound::Builder as TransportBuilder,
};
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
	pub fn parse_url(url: &url::Url) -> Result<(Option<Tag>, Self, TransportBuilder), BoxStdErr> {
		#[cfg(feature = "parse-url-v2rayn")]
		{
			if let Ok(result) = parse_url_v2rayn(url) {
				return Ok(result);
			}
		}
		parse_url_std(url).map(|(s, t)| (None, s, t))
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
			sec: SecurityTypeBuilder::Auto,
			use_legacy_header: false,
		},
		transport,
	))
}

#[cfg(test)]
mod tests {
	use super::{parse_url_std, SettingsBuilder};
	use crate::{proxy::vmess::utils::SecurityTypeBuilder, transport};
	use std::str::FromStr;
	use url::Url;

	#[test]
	fn test_parse_url_std() {
		let data = [
			(
				"vmess://tcp:2e09f64c-c967-4ce3-9498-fdcd8e39e04e-0@google.com:4433/?query=Value1#Connection2",
				(SettingsBuilder {
					addr: "google.com:4433".parse().unwrap(),
					id: "2e09f64c-c967-4ce3-9498-fdcd8e39e04e".parse().unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				}, Default::default()),
			),
			(
				"vmess://ws+tls:7db04e8f-7cfc-46e0-9e18-d329c22ec353-0@myServer.com:12345\
				/?path=%2FmyServerAddressPath%2F%E4%B8%AD%E6%96%87%E8%B7%AF%E5%BE%84%2F&host=www.myServer.com",
				(
					SettingsBuilder {
						addr: "myServer.com:12345".parse().unwrap(),
						id: "7db04e8f-7cfc-46e0-9e18-d329c22ec353".parse().unwrap(),
						sec: SecurityTypeBuilder::Auto,
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
			let (settings, transport) = parse_url_std(&url).unwrap();
			assert_eq!(expected, (settings, transport));
		}
	}
}

#[cfg(feature = "parse-url-v2rayn")]
mod parse_v2rayn_impl {
	use super::{SettingsBuilder, TransportBuilder};
	use crate::{
		prelude::{BoxStdErr, Tag},
		protocol::{SocksAddr, SocksDestination},
		proxy::vmess::utils::SecurityTypeBuilder,
		transport,
	};
	use serde::Deserialize;
	use std::str::FromStr;
	use url::Url;
	use uuid::Uuid;

	#[cfg_attr(test, derive(Debug))]
	#[derive(Deserialize, PartialEq, Eq)]
	#[serde(rename_all = "lowercase")]
	enum Net {
		Tcp,
		Kcp,
		Ws,
		Http,
		H2,
		Quic,
	}

	impl Default for Net {
		fn default() -> Self {
			Net::Tcp
		}
	}

	#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
	#[derive(Deserialize)]
	struct ConfigObject {
		v: usize,
		ps: String,
		add: String,
		port: u16,
		id: Uuid,
		#[serde(default)]
		aid: u16,
		#[serde(default)]
		scy: SecurityTypeBuilder,
		#[serde(default)]
		net: Net,
		#[serde(default, rename = "type")]
		type_: String,
		#[serde(default)]
		host: String,
		#[serde(default)]
		path: String,
		#[serde(default)]
		tls: String,
		#[serde(default)]
		sni: String,
	}

	impl ConfigObject {
		pub fn from_data(encoded_data: &str) -> Result<Self, BoxStdErr> {
			let cfg_str = base64::decode_config(encoded_data, base64::STANDARD_NO_PAD)?;
			let cfg_str = String::from_utf8(cfg_str)?;
			serde_json::from_str(&cfg_str).map_err(Into::into)
		}
	}

	/// Parse `url` using
	/// [v2ray format](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))
	/// .
	pub(super) fn parse_url_v2rayn(
		url: &Url,
	) -> Result<(Option<Tag>, SettingsBuilder, TransportBuilder), BoxStdErr> {
		if !(url.username().is_empty() && url.password().is_none()) {
			return Err("v2rayn format URL should not have username and password".into());
		}
		let encoded_data = url.host_str().ok_or("URL missing host")?;
		// Check if URL is v2rayn format
		let obj = ConfigObject::from_data(encoded_data)?;
		if obj.v != 2 {
			return Err("only version 2 is supported".into());
		}
		if obj.aid != 0 {
			return Err("aid other than 0 (legacy header) is not supported".into());
		}
		if !(obj.type_.is_empty() || obj.type_ == "none") {
			return Err("only 'none` type is supported".into());
		}
		let ps = if obj.ps.is_empty() {
			None
		} else {
			Some(Tag::from(obj.ps.as_str()))
		};
		let addr = {
			let dest = SocksDestination::from_str(&obj.add)
				.map_err(|e| format!("invalid `add` ({})", e))?;
			SocksAddr::new(dest, obj.port)
		};
		let settings = SettingsBuilder {
			addr,
			id: obj.id,
			sec: obj.scy,
			use_legacy_header: false,
		};
		let transport = {
			#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
			{
				let tls_transport = match obj.tls.as_str() {
					"tls" => {
						if !(obj.sni.is_empty() || obj.sni == obj.add) {
							return Err(
								"does not support sni that is not empty or same as add".into()
							);
						}
						Some(crate::transport::tls::OutboundBuilder::default())
					}
					"" => None,
					_ => return Err("invalid tls value, can only be 'tls' or empty".into()),
				};
				match obj.net {
					Net::Tcp => tls_transport.map_or_else(TransportBuilder::default, Into::into),
					#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
					Net::Ws => transport::ws::OutboundBuilder {
						headers: Default::default(),
						path: obj.path,
						host: obj.host,
						tls: tls_transport,
					}
					.into(),
					#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
					Net::Http | Net::H2 => transport::h2::OutboundBuilder {
						host: obj.host,
						path: obj.path,
						tls: tls_transport,
					}
					.into(),
					_ => return Err("net not supported".into()),
				}
			}
			#[cfg(not(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls")))]
			{
				if !obj.tls.is_empty() {
					return Err("TLS not supported".into());
				}
				TransportBuilder::default()
			}
		};
		Ok((ps, settings, transport))
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		#[test]
		fn test_config_object_from_url() {
			let input = Url::from_str(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlSIsInNjeS\
				I6ImF1dG8iLCJ0eXBlIjoiIiwic25pIjoiIiwicGF0aCI6IiIsInBvcnQiOjEwMDAwLCJ2Ijo\
				yLCJob3N0IjoiIiwidGxzIjoiIiwiaWQiOiJlZjdlMjc0Yy04ZWVkLTQ3YTgtYjNkYi04ODY1\
				N2Q0ZmViM2UiLCJuZXQiOiJ3cyJ9",
			)
			.unwrap();
			let expected = ConfigObject {
				v: 2,
				ps: "测试".into(),
				add: "test.test".into(),
				port: 10000,
				id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
				aid: 0,
				scy: SecurityTypeBuilder::Auto,
				net: Net::Ws,
				type_: "".into(),
				host: "".into(),
				path: "".into(),
				tls: "".into(),
				sni: "".into(),
			};
			assert_eq!(
				ConfigObject::from_data(input.host_str().unwrap()).unwrap(),
				expected
			);
		}

		fn check_v2rayn(
			input: &str,
			expected_tag: impl Into<Tag>,
			expected_settings: &SettingsBuilder,
			expected_transport: &TransportBuilder,
		) {
			let input = Url::from_str(input).unwrap();
			let expected_tag = Some(expected_tag.into());
			let (tag, settings, transport) = parse_url_v2rayn(&input).unwrap();
			assert_eq!(&tag, &expected_tag);
			assert_eq!(&settings, expected_settings);
			assert_eq!(&transport, expected_transport);
		}

		#[test]
		fn test_parse_url_v2rayn_plain() {
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlSIsInNjeSI6ImF1dG8iLCJ0eXBl\
					Ijoibm9uZSIsInNuaSI6IiIsInBhdGgiOiIvdGVzdHBhdGgiLCJwb3J0IjoxMDAwMCwidiI6Miwia\
					G9zdCI6InRlc3QuaG9zdCIsInRscyI6IiIsImlkIjoiZWY3ZTI3NGMtOGVlZC00N2E4LWIzZGItOD\
					g2NTdkNGZlYjNlIiwibmV0IjoidGNwIn0=",
				"测试",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::default(),
			);
		}

		#[cfg(any(feature = "tls-transport-openssl", feature = "tls-transport-rustls"))]
		#[test]
		fn test_parse_url_v2rayn_tls() {
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iu\
					a1i+ivlSIsInNjeSI6ImF1dG8iLCJ0eXBlIjoibm9uZSIsInNuaSI6IiIsInBhdGgiOiIiLCJw\
					b3J0IjoxMDAwMCwidiI6MiwiaG9zdCI6IiIsInRscyI6InRscyIsImlkIjoiZWY3ZTI3NGMtOG\
					VlZC00N2E4LWIzZGItODg2NTdkNGZlYjNlIiwibmV0IjoidGNwIn0=",
				"测试",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::Tls(transport::tls::OutboundBuilder::default()),
			);
		}

		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		#[test]
		fn test_parse_url_v2rayn_ws() {
			// With host and path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlXdzIiwic2N5IjoiYXV0byI\
					sInR5cGUiOiIiLCJzbmkiOiIiLCJwYXRoIjoiL3Rlc3RwYXRoIiwicG9ydCI6MTAwMDAsInY\
					iOjIsImhvc3QiOiJ0ZXN0Lmhvc3QiLCJ0bHMiOiIiLCJpZCI6ImVmN2UyNzRjLThlZWQtNDd\
					hOC1iM2RiLTg4NjU3ZDRmZWIzZSIsIm5ldCI6IndzIn0=",
				"测试ws",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::Ws(transport::ws::OutboundBuilder {
					headers: Default::default(),
					path: "/testpath".into(),
					host: "test.host".into(),
					tls: None,
				}),
			);
			// Without host and path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlXdzIiwic2N5IjoiY\
					XV0byIsInR5cGUiOiIiLCJzbmkiOiIiLCJwYXRoIjoiIiwicG9ydCI6MTAwMDAsInY\
					iOjIsImhvc3QiOiIiLCJ0bHMiOiIiLCJpZCI6ImVmN2UyNzRjLThlZWQtNDdhOC1iM\
					2RiLTg4NjU3ZDRmZWIzZSIsIm5ldCI6IndzIn0=",
				"测试ws",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::Ws(transport::ws::OutboundBuilder {
					headers: Default::default(),
					path: Default::default(),
					host: Default::default(),
					tls: None,
				}),
			);
		}

		#[cfg(any(feature = "ws-transport-openssl", feature = "ws-transport-rustls"))]
		#[test]
		fn test_parse_url_v2rayn_wss() {
			// With host and path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlXdzK3RscyIsInNjeSI6I\
					mF1dG8iLCJ0eXBlIjoiIiwic25pIjoiIiwicGF0aCI6Ii90ZXN0cGF0aCIsInBvcnQiOjE\
					wMDAwLCJ2IjoyLCJob3N0IjoidGVzdC5ob3N0IiwidGxzIjoidGxzIiwiaWQiOiJlZjdlM\
					jc0Yy04ZWVkLTQ3YTgtYjNkYi04ODY1N2Q0ZmViM2UiLCJuZXQiOiJ3cyJ9",
				"测试ws+tls",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::Ws(transport::ws::OutboundBuilder {
					headers: Default::default(),
					host: "test.host".into(),
					path: "/testpath".into(),
					tls: Some(transport::tls::OutboundBuilder::default()),
				}),
			);
			// Without host and path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlXdzK3RscyIsInNjeSI\
					6ImF1dG8iLCJ0eXBlIjoiIiwic25pIjoiIiwicGF0aCI6IiIsInBvcnQiOjEwMDAwLCJ\
					2IjoyLCJob3N0IjoiIiwidGxzIjoidGxzIiwiaWQiOiJlZjdlMjc0Yy04ZWVkLTQ3YTg\
					tYjNkYi04ODY1N2Q0ZmViM2UiLCJuZXQiOiJ3cyJ9",
				"测试ws+tls",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::Ws(transport::ws::OutboundBuilder {
					headers: Default::default(),
					path: Default::default(),
					host: Default::default(),
					tls: Some(transport::tls::OutboundBuilder::default()),
				}),
			);
		}

		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		#[test]
		fn test_parse_url_v2rayn_h2() {
			// With path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlWgyIiwic2N5IjoiYXV0\
					byIsInR5cGUiOiIiLCJzbmkiOiIiLCJwYXRoIjoiL3Rlc3RwYXRoIiwicG9ydCI6MTAwM\
					DAsInYiOjIsImhvc3QiOiIiLCJ0bHMiOiIiLCJpZCI6ImVmN2UyNzRjLThlZWQtNDdhOC\
					1iM2RiLTg4NjU3ZDRmZWIzZSIsIm5ldCI6Imh0dHAifQ==",
				"测试h2",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::from(transport::h2::OutboundBuilder {
					host: Default::default(),
					path: "/testpath".into(),
					tls: None,
				}),
			);
			// With host
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlWgyIiwic2N5IjoiY\
					XV0byIsInR5cGUiOiIiLCJzbmkiOiIiLCJwYXRoIjoiIiwicG9ydCI6MTAwMDAsInYiOjIsI\
					mhvc3QiOiJ0ZXN0Lmhvc3QiLCJ0bHMiOiIiLCJpZCI6ImVmN2UyNzRjLThlZWQtNDdhOC1iM\
					2RiLTg4NjU3ZDRmZWIzZSIsIm5ldCI6Imh0dHAifQ==",
				"测试h2",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::from(transport::h2::OutboundBuilder {
					host: "test.host".into(),
					path: Default::default(),
					tls: None,
				}),
			);
			// Without host and path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlWgyIiwic2N5IjoiYXV0\
					byIsInR5cGUiOiIiLCJzbmkiOiIiLCJwYXRoIjoiIiwicG9ydCI6MTAwMDAsInYiOjIsI\
					mhvc3QiOiIiLCJ0bHMiOiIiLCJpZCI6ImVmN2UyNzRjLThlZWQtNDdhOC1iM2RiLTg4Nj\
					U3ZDRmZWIzZSIsIm5ldCI6Imh0dHAifQ==",
				"测试h2",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::from(transport::h2::OutboundBuilder {
					host: Default::default(),
					path: Default::default(),
					tls: None,
				}),
			);
		}

		#[cfg(any(feature = "h2-transport-openssl", feature = "h2-transport-rustls"))]
		#[test]
		fn test_parse_url_v2rayn_h2_tls() {
			// With path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlWgyK3RscyIsInNjeSI6\
					ImF1dG8iLCJ0eXBlIjoiIiwic25pIjoiIiwicGF0aCI6Ii90ZXN0cGF0aCIsInBvcnQiO\
					jEwMDAwLCJ2IjoyLCJob3N0IjoiIiwidGxzIjoidGxzIiwiaWQiOiJlZjdlMjc0Yy04ZW\
					VkLTQ3YTgtYjNkYi04ODY1N2Q0ZmViM2UiLCJuZXQiOiJodHRwIn0=",
				"测试h2+tls",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::from(transport::h2::OutboundBuilder {
					host: Default::default(),
					path: "/testpath".into(),
					tls: Some(transport::tls::OutboundBuilder::default()),
				}),
			);
			// Without host and path
			check_v2rayn(
				"vmess://eyJhZGQiOiJ0ZXN0LnRlc3QiLCJwcyI6Iua1i+ivlWgyK3RscyIs\
					InNjeSI6ImF1dG8iLCJ0eXBlIjoiIiwic25pIjoiIiwicGF0aCI6IiIsInBvcnQiOjEwM\
					DAwLCJ2IjoyLCJob3N0IjoiIiwidGxzIjoidGxzIiwiaWQiOiJlZjdlMjc0Yy04ZWVkLT\
					Q3YTgtYjNkYi04ODY1N2Q0ZmViM2UiLCJuZXQiOiJodHRwIn0=",
				"测试h2+tls",
				&SettingsBuilder {
					addr: SocksAddr::from_str("test.test:10000").unwrap(),
					id: Uuid::from_str("ef7e274c-8eed-47a8-b3db-88657d4feb3e").unwrap(),
					sec: SecurityTypeBuilder::Auto,
					use_legacy_header: false,
				},
				&TransportBuilder::from(transport::h2::OutboundBuilder {
					host: Default::default(),
					path: Default::default(),
					tls: Some(transport::tls::OutboundBuilder::default()),
				}),
			);
		}

		fn check_mixed(
			input: &str,
			expected_tag: Option<&str>,
			expected_settings: &SettingsBuilder,
			expected_transport: &TransportBuilder,
		) {
			let input = Url::from_str(input).unwrap();
			let expected_tag = expected_tag.map(Into::into);
			let (tag, settings, transport) = SettingsBuilder::parse_url(&input).unwrap();
			assert_eq!(&tag, &expected_tag);
			assert_eq!(&settings, expected_settings);
			assert_eq!(&transport, expected_transport);
		}

		#[test]
		fn test_parse_url_mixed() {
			let expected_settings = SettingsBuilder {
				addr: "test.server.com:10000".parse().unwrap(),
				id: "ef7e274c-8eed-47a8-b3db-88657d4feb3e".parse().unwrap(),
				sec: SecurityTypeBuilder::Auto,
				use_legacy_header: false,
			};
			check_mixed(
				"vmess://tcp:ef7e274c-8eed-47a8-b3db-88657d4feb3e@test.server.com:10000?\
						encryption=auto#%E6%B5%8B%E8%AF%95",
				None,
				&expected_settings,
				&Default::default(),
			);
			check_mixed(
				"vmess://eyJhZGQiOiJ0ZXN0LnNlcnZlci5jb20iLCJwcyI6Iua1i+ivlSIsInNjeSI\
				6ImF1dG8iLCJ0eXBlIjoibm9uZSIsInNuaSI6IiIsInBhdGgiOiIiLCJwb3J0IjoxMDAwMCwid\
				iI6MiwiaG9zdCI6IiIsInRscyI6IiIsImlkIjoiZWY3ZTI3NGMtOGVlZC00N2E4LWIzZGItODg\
				2NTdkNGZlYjNlIiwibmV0IjoidGNwIn0=",
				Some("测试"),
				&expected_settings,
				&Default::default(),
			);
		}
	}
}
#[cfg(feature = "parse-url-v2rayn")]
use parse_v2rayn_impl::parse_url_v2rayn;
