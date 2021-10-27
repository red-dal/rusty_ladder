use std::borrow::Cow;
use crate::prelude::BoxStdErr;

pub(super) const WS: &str = "ws";
pub(super) const WSS: &str = "wss";

pub(super) fn make_ws_uri(use_tls: bool, domain: &str, path: &str) -> Result<http::Uri, BoxStdErr> {
	let scheme = if use_tls { WSS } else { WS };
	let path = if path.is_empty() || path.starts_with('/') {
		Cow::Borrowed(path)
	} else {
		format!("/{}", path).into()
	};
	let uri = http::Uri::builder()
		.scheme(scheme)
		.authority(domain)
		.path_and_query(path.as_ref())
		.build()?;
	Ok(uri)
}