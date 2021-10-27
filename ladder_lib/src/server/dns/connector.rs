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

use super::TokioAdapter;
use crate::{
	prelude::{AsyncMutex, Tag},
	protocol::{ProxyContext, ProxyStream},
};
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use lazy_static::lazy_static;
use std::{io, net::SocketAddr, pin::Pin, sync::Arc};
use trust_dns_client::proto::tcp::{Connect, DnsTcpStream};

lazy_static! {
	static ref DOH_DATA: AsyncMutex<Option<ConnectorData>> = AsyncMutex::new(None);
}

struct ConnectorData {
	tag: Tag,
	ctx: Arc<dyn ProxyContext>,
}

pub struct DohTransportStream(TokioAdapter<ProxyStream>);

impl DohTransportStream {
	pub async fn register(ctx: Arc<dyn ProxyContext>, tag: Tag) {
		*DOH_DATA.lock().await = Some(ConnectorData { tag, ctx });
	}
}

impl AsyncRead for DohTransportStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut [u8],
	) -> std::task::Poll<io::Result<usize>> {
		Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
	}
}

impl AsyncWrite for DohTransportStream {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<io::Result<usize>> {
		Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
	}

	fn poll_flush(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().0).poll_flush(cx)
	}

	fn poll_close(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().0).poll_close(cx)
	}
}

impl DnsTcpStream for DohTransportStream {
	type Time = trust_dns_client::proto::TokioTime;
}

#[async_trait]
impl Connect for DohTransportStream {
	async fn connect(addr: SocketAddr) -> io::Result<Self> {
		let mut data = DOH_DATA.lock().await;
		let data = data
			.as_mut()
			.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "DOH connector not initialized"))?;
		let connector = data
			.ctx
			.get_tcp_connector(&data.tag)
			.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
		let stream = connector
			.connect(&addr.into(), data.ctx.as_ref())
			.await
			.map_err(crate::protocol::outbound::Error::into_io_err)?;
		Ok(Self(TokioAdapter(stream)))
	}
}
