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

pub use crate::protocol::{SocksAddr, SocksDestination};
pub use async_trait::async_trait;
pub use bytes::{Buf, BufMut};
pub use log::{debug, error, info, trace, warn};
pub use rand::{Rng, RngCore};
pub use std::{
	borrow::Cow,
	convert::{TryFrom, TryInto},
	error::Error as StdErr,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	pin::Pin,
	str::FromStr,
	sync::Arc,
};
pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub type Tag = smol_str::SmolStr;
#[allow(dead_code)]
pub type AsyncMutex<T> = futures::lock::Mutex<T>;
pub type BoxStdErr = Box<dyn StdErr + Send + Sync>;

#[allow(dead_code)]
pub const CRLF: &[u8] = b"\r\n";
#[allow(dead_code)]
pub const CRLF_2: &[u8] = b"\r\n\r\n";
