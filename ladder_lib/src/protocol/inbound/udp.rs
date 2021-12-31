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

use crate::{prelude::*, protocol::common::GetProtocolName};
use async_trait::async_trait;
use std::io;
use tokio::net::UdpSocket;

#[async_trait]
pub trait Acceptor: GetProtocolName {
	async fn accept_udp(&self, sock: UdpSocket) -> Result<DatagramStream, BoxStdErr>;
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct Session {
	/// Address for local client (source)
	pub src: SocketAddr,
	/// Address for remote server (destination)
	pub dst: SocksAddr,
}

pub struct DatagramInfo {
	pub len: usize,
	pub src: Option<SocketAddr>,
	pub dst: SocksAddr,
}

#[async_trait]
pub trait RecvDatagram: Unpin + Send + Sync {
	async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<DatagramInfo>;
}

#[async_trait]
pub trait SendDatagram: Unpin + Send + Sync {
	async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize>;
}

#[async_trait]
impl<T: RecvDatagram + ?Sized> RecvDatagram for Box<T> {
	async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<DatagramInfo> {
		self.as_mut().recv_inbound(buf).await
	}
}

#[async_trait]
impl<T: SendDatagram + ?Sized> SendDatagram for Box<T> {
	async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize> {
		self.as_mut().send_inbound(sess, buf).await
	}
}

pub struct DatagramStream {
	pub read_half: Box<dyn RecvDatagram>,
	pub write_half: Box<dyn SendDatagram>,
}

#[async_trait]
impl RecvDatagram for DatagramStream {
	async fn recv_inbound(&mut self, buf: &mut [u8]) -> io::Result<DatagramInfo> {
		self.read_half.recv_inbound(buf).await
	}
}

#[async_trait]
impl SendDatagram for DatagramStream {
	async fn send_inbound(&mut self, sess: &Session, buf: &[u8]) -> io::Result<usize> {
		self.write_half.send_inbound(sess, buf).await
	}
}
