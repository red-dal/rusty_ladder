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

#![allow(clippy::doc_markdown)]

/*!
## Get connections info
```not_rust
GET /connections
```
Parameters:
- secret (string): secret in the server configuration
- ids (string, optional): filter connections with id or ids (multiple ids are separated by ',')
- inbounds (string, optional): filter connections with inbound tags (multiple tags are separated by ',')
- outbounds (string, optional): filter connections with outbound tags (multiple tags are separated by ',')
- state (string, optional): filter connections with specific state, this can be one of: all, alive, dead

Response: Array of serialized [`Snapshot`] objects, each representing one connection.

Each snapshot object contains:

| Name        |     Type     | Description                                                                                  |
|-------------|:------------:|----------------------------------------------------------------------------------------------|
| conn_id     | string       | String version of u64 connection id.                                                         |
| inbound_ind | int          |                                                                                              |
| inbound_tag | string       |                                                                                              |
| start_time  | float        |                                                                                              |
| from        | string       | Source of the connection.                                                                    |
| end_time    | float        | If existed and not none, the connection is dead;<br>otherwise the connection is still alive. |
| state       | State object |                     Details information that depends on connection state.                    |

When handshaking, State object:

| Name |  Type  | Description               |
|------|:------:|---------------------------|
| type | string | Can only be 'Handshaking' |

When connecting, State object:

| Name         |  Type  | Description                   |
|--------------|:------:|-------------------------------|
| type         | string | Can only be 'Connecting'      |
| to           | string | Destination of the connection |
| outbound_ind | int    |                               |
| outbound_tag | string |                               |

When proxying, State object:

| Name         |  Type  | Description                                            |
|--------------|:------:|--------------------------------------------------------|
| type         | string | Can only be 'Connecting'                               |
| to           | string | Destination of the connection                          |
| outbound_ind | int    |                                                        |
| outbound_tag | string |                                                        |
| recv         | int    | Number of bytes received (from destination to source). |
| send         | int    | Number of bytes sent (from source to destination).     |
| recv_speed   | int    | Estimated receive speed in bytes per second.           |
| send_speed   | int    | Estimated send speed in bytes per second.              |

Example:
```not_rust
GET /connections
GET /connections?inbounds=socks,http&outbounds=vmess
```
*/

use super::Monitor;
use crate::prelude::{BoxStdErr, Tag};
use smol_str::SmolStr;
use std::{net::SocketAddr, str::FromStr};
use warp::Filter;

pub(super) mod serde_conn_id {
	use serde::Serializer;

	#[allow(clippy::trivially_copy_pass_by_ref)]
	pub fn serialize<S>(id: &u64, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let val = format!("{:#x}", id);
		serializer.serialize_str(&val)
	}
}

const CONNECTIONS: &str = "connections";

#[derive(serde::Deserialize)]
struct RequestParams {
	secret: Box<str>,
	ids: Option<Box<str>>,
	inbounds: Option<Box<str>>,
	outbounds: Option<Box<str>>,
	state: Option<Box<str>>,
}

pub async fn serve_web_api(
	monitor: Monitor,
	addr: &SocketAddr,
	secret: SmolStr,
) -> Result<(), BoxStdErr> {
	log::info!("Serving Web API on {}", addr);
	let cors = warp::cors()
		.allow_any_origin()
		.allow_method(http::Method::GET);
	let filter = warp::get()
		.and(warp::path(CONNECTIONS))
		.and(warp::path::end())
		.and(warp::filters::query::query::<RequestParams>())
		.and_then(move |params| {
			let monitor = monitor.clone();
			let secret = secret.clone();
			async move { get_connections(params, &monitor, &secret) }
		})
		.with(cors);
	warp::serve(filter).bind(*addr).await;
	Ok(())
}

fn get_connections(
	mut params: RequestParams,
	monitor: &Monitor,
	secret: &SmolStr,
) -> Result<warp::reply::Json, warp::Rejection> {
	fn str_to_list(val: &str) -> Vec<Tag> {
		val.split(',').map(Tag::new).collect::<Vec<_>>()
	}
	fn turn_none_if_empty(val: &mut Option<Box<str>>) {
		if let Some(inner) = val {
			if inner.is_empty() {
				*val = None;
			}
		}
	}
	if params.secret.as_ref() != secret {
		return Err(warp::reject());
	}
	turn_none_if_empty(&mut params.ids);
	turn_none_if_empty(&mut params.inbounds);
	turn_none_if_empty(&mut params.outbounds);
	turn_none_if_empty(&mut params.state);
	let params = params;

	let conn_ids = {
		if let Some(ids_str) = &params.ids {
			let mut ids = Vec::new();
			for val in ids_str.split(',') {
				let id = u64::from_str(val).map_err(|_| {
					log::error!("query 'ids' ('{}') contains invalid id", ids_str);
					warp::reject()
				})?;
				ids.push(id);
			}
			Some(ids)
		} else {
			None
		}
	};
	let inbound_tags = params.inbounds.as_ref().map(|s| str_to_list(s));
	let outbound_tags = params.outbounds.as_ref().map(|s| str_to_list(s));
	let state = {
		if let Some(state) = &params.state {
			match super::StateFilter::from_str(state) {
				Ok(state) => state,
				Err(e) => {
					log::error!("{}", e);
					return Err(warp::reject());
				}
			}
		} else {
			super::StateFilter::All
		}
	};
	let filter = super::Filter {
		conn_ids,
		inbound_tags,
		outbound_tags,
		state,
	};
	let mut result = Vec::new();
	monitor.query(&filter, &mut result);

	Ok(warp::reply::json(&result))
}
