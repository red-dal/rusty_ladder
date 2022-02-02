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