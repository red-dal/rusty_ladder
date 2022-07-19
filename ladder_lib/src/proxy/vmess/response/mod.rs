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

use super::{HeaderMode, Iv, Key};

#[cfg(any(feature = "vmess-outbound-openssl", feature = "vmess-outbound-ring"))]
pub(super) use aead::{open_len, open_payload};

#[derive(Debug)]
pub struct Response {
	pub v: u8,
	opt: u8,
	cmd: u8,
	cmd_len: u8,
}

impl Response {
	pub fn new(v: u8) -> Response {
		Response {
			v,
			opt: 0,     // discarded, use 0
			cmd: 0,     // dynamic port, use 0
			cmd_len: 0, // same as above, use 0
		}
	}

	pub fn parse(buf: &[u8]) -> Response {
		debug_assert!(buf.len() >= 4);
		// trace!("Decrypt vmess response with aes128cfb",);

		let v = buf[0];
		let opt = buf[1];
		let cmd = buf[2];
		let cmd_len = buf[3];

		// ignore dynamic port

		Response {
			v,
			opt,
			cmd,
			cmd_len,
		}
	}

	pub fn encode(&self, response_key: &Key, response_iv: &Iv, mode: super::HeaderMode) -> Vec<u8> {
		let response_buf = [self.v, self.opt, self.cmd, self.cmd_len];
		match mode {
			HeaderMode::Aead => aead::seal_response(&response_buf, response_key, response_iv),
		}
	}
}
