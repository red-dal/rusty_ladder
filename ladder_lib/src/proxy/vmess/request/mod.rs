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

mod aead;

use super::{
	utils::{self, AddrType, Iv, Key, SecurityType},
	HeaderMode,
};
use crate::prelude::*;
use num_enum::TryFromPrimitive;
use std::io;
use thiserror::Error as ThisError;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct OptionFlags(u8);

macro_rules! impl_flag_option {
	($set:ident, $get:ident, $clear:ident, $mask:ident) => {
		#[inline]
		pub fn $set(&mut self) {
			self.set(Self::$mask);
		}

		#[inline]
		pub fn $get(&self) -> bool {
			self.get(Self::$mask)
		}

		#[inline]
		pub fn $clear(&mut self) {
			self.clear(Self::$mask);
		}
	};
}

#[allow(dead_code)]
impl OptionFlags {
	// See more at
	// https://github.com/v2fly/v2ray-core/blob/3c17276462e8552771808d42f770c29bd0a0a5b5/common/protocol/headers.go

	/// Request payload is chunked. Each chunk consists of length, authentication and payload.
	pub const CHUNK_STREAM: OptionFlags = OptionFlags(0x01);
	/// Client side expects to reuse the connection.
	pub const CONNECTION_REUSE: OptionFlags = OptionFlags(0x02);
	pub const CHUNK_MASKING: OptionFlags = OptionFlags(0x04);
	pub const GLOBAL_PADDING: OptionFlags = OptionFlags(0x08);
	pub const AUTHENTICATED_LENGTH: OptionFlags = OptionFlags(0x10);

	#[inline]
	pub fn value(self) -> u8 {
		self.0
	}

	#[inline]
	pub fn set(&mut self, mask: OptionFlags) {
		self.0 |= mask.0;
	}

	#[inline]
	pub fn clear(&mut self, mask: OptionFlags) {
		self.0 &= !mask.0;
	}

	#[inline]
	pub fn get(self, mask: OptionFlags) -> bool {
		(self.0 & mask.0) != 0
	}

	impl_flag_option!(
		set_chunk_stream,
		chunk_stream,
		clear_chunk_stream,
		CHUNK_STREAM
	);
	impl_flag_option!(
		set_connection_reuse,
		connection_reuse,
		clear_connection_reuse,
		CONNECTION_REUSE
	);
	impl_flag_option!(
		set_chunk_masking,
		chunk_masking,
		clear_chunk_masking,
		CHUNK_MASKING
	);
	impl_flag_option!(
		set_global_padding,
		global_padding,
		clear_global_padding,
		GLOBAL_PADDING
	);
	impl_flag_option!(
		set_authenticated_length,
		authenticated_length,
		clear_authenticated_length,
		AUTHENTICATED_LENGTH
	);
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum Command {
	Tcp = 1,
	Udp = 2,
}

impl Default for Command {
	fn default() -> Self {
		Command::Tcp
	}
}

#[derive(Debug)]
pub struct Request {
	pub payload_iv: Iv,
	pub payload_key: Key,
	/// Verification number used to verify server response.  
	/// A random number is recommended.
	pub v: u8,
	/// Number of bytes used as padding, must be within [0, 16).  
	/// If `p` is equal or larger than 16, `p` % 16 will be used.
	pub p: u8,
	pub opt: OptionFlags,
	pub sec: SecurityType,
	pub cmd: Command,
	pub dest_addr: SocksAddr,
}

impl Request {
	pub fn new(payload_iv: &Iv, payload_key: &Key, dest_addr: SocksAddr, cmd: Command) -> Self {
		Self {
			dest_addr,
			v: 0,
			p: 0,
			opt: OptionFlags::CHUNK_STREAM,
			cmd,
			payload_iv: *payload_iv,
			payload_key: *payload_key,
			sec: SecurityType::default(),
		}
	}

	#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
	pub fn encode_aead(&self, uuid: &Uuid, time: i64) -> Vec<u8> {
		trace!("Encoding VMess request using AEAD");
		let cmd_key = utils::new_cmd_key(uuid);
		let mut tmp_buf = Vec::with_capacity(128);
		write_request_to(self, &mut tmp_buf);
		aead::seal_request(&tmp_buf, &cmd_key, time)
	}

	pub async fn decode<R>(
		stream: &mut R,
		#[allow(unused_variables)] id: &Uuid,
		cmd_key: &[u8; 16],
		auth_id: &[u8; 16],
		#[allow(unused_variables)] time: i64,
		mode: HeaderMode,
	) -> Result<Request, ReadRequestError>
	where
		R: AsyncRead + Unpin + 'static,
	{
		Ok(match mode {
			HeaderMode::Aead => {
				trace!("Reading AEAD VMess request header");
				let request = read_aead(stream, cmd_key, auth_id).await?;
				trace!("AEAD VMess request: {:?}", request);
				request
			}
		})
	}
}

async fn read_aead<R>(
	stream: &mut R,
	cmd_key: &[u8; 16],
	auth_id: &[u8; 16],
) -> Result<Request, ReadRequestError>
where
	R: AsyncRead + Unpin,
{
	let mut buffer = Vec::with_capacity(256);
	buffer.resize(18 + 8, 0);
	stream.read_exact(&mut buffer).await?;
	let (len_buf, nonce) = buffer.split_at_mut(18);

	let mut conn_nonce = [0_u8; 8];
	conn_nonce.copy_from_slice(nonce);

	let len = match aead::open_len(len_buf, &conn_nonce, cmd_key, auth_id) {
		Ok(len) => len,
		Err(err) => {
			let msg = format!("cannot decrypt VMess AEAD length ({})", err);
			return Err(msg.into());
		}
	};

	buffer.resize(len + 16, 0);
	stream.read_exact(&mut buffer).await?;

	let payload = match aead::open_payload(&mut buffer, &conn_nonce, cmd_key, auth_id) {
		Ok(payload) => payload,
		Err(err) => {
			let msg = format!("cannot decrypt VMess AEAD payload ({})", err);
			return Err(msg.into());
		}
	};

	let mut cursor = io::Cursor::new(payload);
	let request = match read_request(&mut cursor).await {
		Ok(req) => req,
		Err(err) => match err {
			ReadRequestError::Io(e) => {
				panic!(
					"Programming error: AEAD cursor should not return any IO error: {}",
					e
				);
			}
			ReadRequestError::Invalid(e) => {
				return Err(ReadRequestError::Invalid(e));
			}
		},
	};

	Ok(request)
}

async fn read_request<R>(reader: &mut R) -> Result<Request, ReadRequestError>
where
	R: AsyncRead + Unpin,
{
	let mut buffer = Vec::with_capacity(512);

	buffer.resize(41, 0);
	reader.read_exact(&mut buffer).await?;

	let mut tmp_buf = buffer.as_slice();

	// version, 1 byte
	let ver = tmp_buf.get_u8();
	if ver != 1 {
		return Err(format!("invalid request version {}, only 1 is allowed", ver).into());
	}

	// IV, 16 bytes
	let payload_iv = {
		let mut iv = [0_u8; 16];
		tmp_buf.copy_to_slice(&mut iv);
		iv
	};

	// key, 16 bytes
	let payload_key = {
		let mut key = [0_u8; 16];
		tmp_buf.copy_to_slice(&mut key);
		key
	};

	// verification code, 1 byte
	let v = tmp_buf.get_u8();

	// option flags, 1 byte
	let opt = OptionFlags(tmp_buf.get_u8());

	// p and sec, 1 byte
	let (p, sec) = {
		let tmp = tmp_buf.get_u8();
		trace!("Reading p and sec from {}", tmp);
		let sec_value = tmp & 0xf;
		let p = tmp >> 4;

		let sec = if let Ok(sec) = SecurityType::try_from(sec_value) {
			sec
		} else {
			return Err(format!("invalid security option {}", sec_value).into());
		};

		(p, sec)
	};
	trace!("padding random bytes count: {}", p);

	// 1 reserved byte
	let _reserved = tmp_buf.get_u8();

	// TCP/UDP, 1 byte
	let cmd = tmp_buf.get_u8();
	let cmd = if let Ok(cmd) = Command::try_from(cmd) {
		cmd
	} else {
		return Err(format!("invalid request command {}", cmd).into());
	};

	// port, 2 byte
	let port = tmp_buf.get_u16();

	// address type, 1 byte
	let atyp = tmp_buf.get_u8();
	let atyp = if let Ok(atyp) = AddrType::try_from(atyp) {
		atyp
	} else {
		return Err(format!("invalid address type {}", atyp).into());
	};

	let dest = read_dest_into(atyp, reader, &mut buffer).await?;

	// random bytes, `p` bytes
	// 16 bytes max
	if p > 0 {
		let p = p as usize;

		let pos = buffer.len();
		buffer.resize(buffer.len() + p, 0);
		reader.read_exact(&mut buffer[pos..]).await?;
	}
	trace!("Total request buffer length: {}", buffer.len());

	// FNV1a hash, 4 bytes

	let hash = reader.read_u32().await?;
	let calculated_hash = utils::fnv1a(&buffer);

	if hash != calculated_hash {
		debug!(
			"VMess request hash: {:x}, buf calculated hash: {:x}",
			hash, calculated_hash
		);
		return Err("request fnv1a hash check failed".into());
	}

	let target_addr = SocksAddr::new(dest, port);
	let mut request = Request::new(&payload_iv, &payload_key, target_addr, cmd);
	request.v = v;
	request.p = p;
	request.opt = opt;
	request.sec = sec;
	request.cmd = cmd;
	Ok(request)
}

async fn read_dest_into<R: AsyncRead + Unpin>(
	atyp: AddrType,
	reader: &mut R,
	buffer: &mut Vec<u8>,
) -> Result<SocksDestination, ReadRequestError> {
	use crate::protocol::socks_addr::{AddrType as SocksAddrType, ReadError};
	let socks_atyp = match atyp {
		AddrType::Ipv4 => SocksAddrType::Ipv4,
		AddrType::Name => SocksAddrType::Name,
		AddrType::Ipv6 => SocksAddrType::Ipv6,
	};

	let dest = SocksDestination::async_read_from_atyp(reader, socks_atyp)
		.await
		.map_err(|e| match e {
			ReadError::Io(e) => ReadRequestError::Io(e),
			_ => ReadRequestError::Invalid(e.into()),
		})?;

	dest.write_to_no_atyp(buffer);

	Ok(dest)
}

#[derive(Debug, ThisError)]
pub enum ReadRequestError {
	#[error("read request IO error ({0})")]
	Io(io::Error),
	#[error("invalid request ({0})")]
	Invalid(BoxStdErr),
}

impl From<io::Error> for ReadRequestError {
	fn from(e: io::Error) -> Self {
		ReadRequestError::Io(e)
	}
}

impl From<Cow<'static, str>> for ReadRequestError {
	fn from(value: Cow<'static, str>) -> Self {
		ReadRequestError::Invalid(value.into())
	}
}

impl From<&'static str> for ReadRequestError {
	fn from(value: &'static str) -> Self {
		ReadRequestError::Invalid(value.into())
	}
}

impl From<String> for ReadRequestError {
	fn from(value: String) -> Self {
		ReadRequestError::Invalid(value.into())
	}
}

#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
fn write_request_to(request: &Request, request_buf: &mut Vec<u8>) -> usize {
	let start_pos = request_buf.len();

	// ver
	request_buf.put_u8(1);
	// iv
	request_buf.put_slice(&request.payload_iv);
	// key
	request_buf.put_slice(&request.payload_key);
	// verification number, should be random number
	request_buf.put_u8(request.v);

	request_buf.put_u8(request.opt.value());

	// insert p bytes of random bytes before the actual verification
	let p: u8 = request.p % 16;
	// security settings
	let sec = request.sec as u8;
	request_buf.put_u8((p << 4) | sec);

	// 1 byte reserve
	request_buf.put_u8(0);

	// cmd
	request_buf.put_u8(request.cmd as u8);

	// port
	request_buf.put_u16(request.dest_addr.port);

	// address
	match &request.dest_addr.dest {
		SocksDestination::Ip(ip) => match ip {
			IpAddr::V4(ip) => {
				request_buf.put_u8(AddrType::Ipv4 as u8);
				request_buf.put_slice(ip.octets().as_ref());
			}
			IpAddr::V6(ip) => {
				request_buf.put_u8(AddrType::Ipv6 as u8);
				request_buf.put_slice(ip.octets().as_ref());
			}
		},
		SocksDestination::Name(name) => {
			// Domain name length should not be larger than 255.
			request_buf.put_u8(AddrType::Name as u8);
			request_buf.put_u8(name.len());
			request_buf.put_slice(name.as_bytes());
		}
	}

	// p bytes of random number
	if p > 0 {
		let old_len = request_buf.len();
		request_buf.resize(old_len + p as usize, 0);
		let mut rng = rand::thread_rng();
		rng.fill_bytes(&mut request_buf[old_len..]);
	}

	// fnv1a hash of all above bytes
	let f = utils::fnv1a(&request_buf[start_pos..]);
	request_buf.put_u32(f);

	start_pos
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::timestamp_now;
	use rand::rngs::OsRng;

	pub(super) fn init_test() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	#[test]
	fn test_read_request_aead() {
		init_test();
		let id = Uuid::from_str("27848739-7e62-4138-9fd3-098a63964b6b").unwrap();
		let time = timestamp_now();
		let cmd_key = utils::new_cmd_key(&id);
		let target_addr = SocksAddr::new(
			SocksDestination::Ip(Ipv4Addr::new(127, 0, 0, 1).into()),
			1080,
		);

		let mut rng = OsRng;
		let payload_key = rng.gen();
		let payload_iv = rng.gen();

		let mut request = Request::new(&payload_iv, &payload_key, target_addr, Command::Tcp);

		request.sec = SecurityType::auto();
		request.p = rng.gen_range(0..16);
		request.v = rng.gen();

		info!("{:#?}", request);

		tokio::runtime::Runtime::new().unwrap().block_on(async move {
			let buffer = request.encode_aead(&id, time);
			let (auth_id, data) = buffer.split_at(16);
			let data = data.to_owned();
			let mut cursor = io::Cursor::new(data);
			let res = read_aead(&mut cursor, &cmd_key, auth_id.try_into().unwrap()).await;
			let result_request = res.unwrap();
			assert_eq!(request.payload_iv, result_request.payload_iv);
			assert_eq!(request.payload_key, result_request.payload_key);
			assert_eq!(request.v, result_request.v);
			assert_eq!(request.p, result_request.p);
		});
	}
}
