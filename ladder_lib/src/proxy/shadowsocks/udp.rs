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

/*!
Shadowsocks UDP Request (before encrypted)
```plain
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+
```

Shadowsocks UDP Response (before encrypted)
```plain
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+
```

Shadowsocks UDP Request and Response (after encrypted)
```plain
+-------+--------------+
|   IV  |    PAYLOAD   |
+-------+--------------+
| Fixed |   Variable   |
+-------+--------------+
```
*/

use super::{key_to_session_key, utils::salt_len, Error};
use crate::{
	prelude::*,
	protocol::{
		outbound::udp::socket::{RecvDatagram, SendDatagram},
		socks_addr::ReadError,
	},
	utils::crypto::aead::{
		nonce::CounterSequence, Algorithm, Decrypt, Decryptor, Encrypt, Encryptor, TAG_LEN,
	},
};
use bytes::Bytes;
use rand::thread_rng;
use std::io;

const MAX_DATAGRAM_SIZE: usize = 8 * 1024;
pub(super) const EMPTY_AAD: &[u8] = &[];

pub struct WriteHalf {
	inner: Box<dyn SendDatagram>,
	write_helper: WriteHelper,
}

impl WriteHalf {
	pub fn new(
		inner: Box<dyn SendDatagram>,
		algo: Algorithm,
		remote_addr: SocksAddr,
		password: Bytes,
	) -> Self {
		let write_helper = WriteHelper::new(algo, remote_addr, password);
		Self {
			inner,
			write_helper,
		}
	}
}

pub struct ReadHalf {
	inner: Box<dyn RecvDatagram>,
	read_helper: ReadHelper,
}

impl ReadHalf {
	pub fn new(inner: Box<dyn RecvDatagram>, algo: Algorithm, password: Bytes) -> Self {
		let read_helper = ReadHelper::new(algo, password);
		Self { inner, read_helper }
	}
}

#[async_trait]
impl RecvDatagram for ReadHalf {
	async fn recv_src(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocksAddr)> {
		return self.read_helper.recv_src(self.inner.as_mut(), buf).await;
	}
}

#[async_trait]
impl SendDatagram for WriteHalf {
	#[inline]
	async fn send_dst(&mut self, dst: &SocksAddr, payload: &[u8]) -> std::io::Result<usize> {
		return self
			.write_helper
			.send_dst(self.inner.as_mut(), dst, payload)
			.await;
	}

	async fn shutdown(&mut self) -> std::io::Result<()> {
		return Ok(());
	}
}

struct WriteHelper {
	algo: Algorithm,
	buffer: Vec<u8>,
	remote_addr: SocksAddr,
	password: Bytes,
}

impl WriteHelper {
	pub fn new(algo: Algorithm, remote_addr: SocksAddr, password: Bytes) -> Self {
		Self {
			algo,
			remote_addr,
			buffer: Vec::with_capacity(MAX_DATAGRAM_SIZE),
			password,
		}
	}

	async fn send_dst<W>(
		&mut self,
		writer: &mut W,
		addr: &SocksAddr,
		payload: &[u8],
	) -> std::io::Result<usize>
	where
		W: SendDatagram + ?Sized,
	{
		let buffer = &mut self.buffer;

		// generate random salt
		// this should be unique
		buffer.resize(salt_len(self.algo), 0);
		thread_rng().fill_bytes(buffer);

		let mut enc = Encryptor::new_encryptor(
			key_to_session_key(&self.password, buffer, self.algo),
			CounterSequence::default(),
		)
		.expect("invalid key length for AEAD encryptor in WriteHelper");

		buffer.reserve(addr.serialized_len_atyp() + payload.len() + TAG_LEN);

		let pos = buffer.len();
		encode_payload(buffer, addr, payload);

		enc.seal_inplace_append_tag(pos, buffer, EMPTY_AAD)
			.expect("failed to encrypt datagram");

		return writer.send_dst(&self.remote_addr, buffer).await;
	}
}

struct ReadHelper {
	algo: Algorithm,
	password: Bytes,
}

impl ReadHelper {
	fn new(algo: Algorithm, password: Bytes) -> Self {
		Self { algo, password }
	}

	async fn recv_src<R>(
		&mut self,
		reader: &mut R,
		dest: &mut [u8],
	) -> std::io::Result<(usize, SocksAddr)>
	where
		R: RecvDatagram + ?Sized,
	{
		let salt_len = salt_len(self.algo);
		debug_assert!(dest.len() > salt_len + TAG_LEN);

		// ignore source addr
		let (len, _src_addr) = reader.recv_src(dest).await?;
		// buffer for handling the datagram
		let dest = &mut dest[..len];

		// buffer must be large enough to contain at least the salt and the AEAD tag
		if len <= salt_len + TAG_LEN {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				Error::DatagramTooSmall(len),
			));
		}

		// extract salt
		let (salt, addr_payload_tag) = dest.split_at_mut(salt_len);

		// init decryptor
		let mut dec = Decryptor::new_decryptor(
			key_to_session_key(&self.password, salt, self.algo),
			CounterSequence::default(),
		)
		.expect("invalid key length for AEAD decryptor in ReadHelper");
		// decrypt
		let addr_payload = match dec.open_inplace(addr_payload_tag, EMPTY_AAD) {
			Ok(payload) => payload,
			Err(err) => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					Error::FailedCrypto(err),
				))
			}
		};
		// extract target address
		let (addr, addr_len) =
			SocksAddr::read_from_bytes(addr_payload).map_err(ReadError::into_io_err)?;
		let addr_len = usize::from(addr_len.get());
		// extract payload
		let payload = &addr_payload[addr_len..];
		let payload_len = payload.len();
		// starting position of payload in the buffer
		let payload_pos = salt_len + addr_len;

		// move payload to the front of the buffer
		dest.copy_within(payload_pos..payload_pos + payload_len, 0);
		Ok((payload_len, addr))
	}
}

fn encode_payload<B: BufMut>(buffer: &mut B, dst: &SocksAddr, payload: &[u8]) {
	dst.write_to(buffer);
	buffer.put_slice(payload);
}

struct PlainWriteHelper {
	buffer: Vec<u8>,
	remote_addr: SocksAddr,
}

impl PlainWriteHelper {
	fn new(remote_addr: SocksAddr) -> Self {
		Self {
			buffer: Vec::with_capacity(MAX_DATAGRAM_SIZE),
			remote_addr,
		}
	}

	async fn send_dst<W>(
		&mut self,
		writer: &mut W,
		dst: &SocksAddr,
		payload: &[u8],
	) -> std::io::Result<usize>
	where
		W: SendDatagram + ?Sized,
	{
		self.buffer.clear();
		encode_payload(&mut self.buffer, dst, payload);
		return writer.send_dst(&self.remote_addr, &self.buffer).await;
	}
}

struct PlainReadHelper {}

impl PlainReadHelper {
	async fn recv_src<R>(
		&mut self,
		reader: &mut R,
		buf: &mut [u8],
	) -> std::io::Result<(usize, SocksAddr)>
	where
		R: RecvDatagram + ?Sized,
	{
		debug_assert!(buf.len() > 16);
		let (len, _src_addr) = reader.recv_src(buf).await?;
		// buffer for handling the datagram
		let buffer = &mut buf[..len];

		let (src, addr_len) = SocksAddr::read_from_bytes(buffer).map_err(ReadError::into_io_err)?;
		let addr_len = usize::from(addr_len.get());
		// length of the payload bytes
		let payload_len = buffer.len() - addr_len;
		// starting position of the payload bytes in the buffer
		let payload_pos = addr_len;
		// copy all payload bytes to the front of the buffer
		buffer.copy_within(payload_pos..payload_pos + payload_len, 0);
		Ok((payload_len, src))
	}
}

pub struct PlainReadHalf {
	inner: Box<dyn RecvDatagram>,
	helper: PlainReadHelper,
}

impl PlainReadHalf {
	pub fn new(inner: Box<dyn RecvDatagram>) -> Self {
		Self {
			inner,
			helper: PlainReadHelper {},
		}
	}
}

pub struct PlainWriteHalf {
	inner: Box<dyn SendDatagram>,
	helper: PlainWriteHelper,
}

impl PlainWriteHalf {
	pub fn new(inner: Box<dyn SendDatagram>, remote_addr: SocksAddr) -> Self {
		Self {
			inner,
			helper: PlainWriteHelper::new(remote_addr),
		}
	}
}

#[async_trait]
impl SendDatagram for PlainWriteHalf {
	#[inline]
	async fn send_dst(&mut self, dst: &SocksAddr, payload: &[u8]) -> std::io::Result<usize> {
		self.helper
			.send_dst(self.inner.as_mut(), dst, payload)
			.await
	}

	async fn shutdown(&mut self) -> std::io::Result<()> {
		return Ok(());
	}
}

#[async_trait]
impl RecvDatagram for PlainReadHalf {
	#[inline]
	async fn recv_src(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocksAddr)> {
		return self.helper.recv_src(self.inner.as_mut(), buf).await;
	}
}
