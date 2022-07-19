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

mod alter_ids;
mod tcp;
#[cfg(feature = "use-udp")]
mod udp;

use super::{
	aead_header::auth_id,
	request::ReadRequestError,
	utils::{new_cmd_key, new_response_key_and_iv, AuthId, Error, PartialId},
	Command, HeaderMode, Request, Response, SecurityType,
};
use crate::{
	prelude::*,
	protocol::{
		inbound::{AcceptError, AcceptResult, PlainHandshakeHandler, SessionInfo, TcpAcceptor},
		AsyncReadWrite, BufBytesStream, GetProtocolName,
	},
	utils::{crypto::aead::Algorithm, timestamp_now},
};
use uuid::Uuid;

/// Maximum allowed absolute difference between the time in auth from client and server current time.
const MAX_TIMESTAMP_DIFF: u64 = 120;

// -----------------------------------------------------------
//                         Builder
// -----------------------------------------------------------

#[derive(Debug, Default)]
#[cfg_attr(
	feature = "use_serde",
	derive(serde::Deserialize),
	serde(deny_unknown_fields)
)]
pub struct SettingsBuilder {
	pub users: Vec<User>,
}

impl SettingsBuilder {
	/// Creates a `VMess` inbound [`Settings`].
	///
	/// # Errors
	///
	/// Returns an error if error occurred when building `self.transport`.
	pub fn build(self) -> Result<Settings, BoxStdErr> {
		if self.users.is_empty() {
			return Err("VMess inbound must have at least one user".into());
		}
		Ok(Settings {
			users: self.users.into_iter().collect(),
			container: auth_id::GuardedContainer::new(MAX_TIMESTAMP_DIFF),
		})
	}
}

impl crate::protocol::DisplayInfo for SettingsBuilder {
	fn fmt_brief(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("vmess-in")
	}

	fn fmt_detail(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("vmess-in(")?;
		let mut first = true;
		for u in &self.users {
			if first {
				first = false;
			} else {
				f.write_str(",")?;
			}
			let id = PartialId(&u.id);
			write!(f, "'{id}*'")?;
		}
		if !first {
			f.write_str(")")?;
		}
		Ok(())
	}
}

// -----------------------------------------------------------
//                         Settings
// -----------------------------------------------------------

pub struct Settings {
	users: Vec<User>,
	container: auth_id::GuardedContainer,
}

impl Settings {
	#[inline]
	async fn check_auth_aead(&self, auth_id: &AuthId) -> Option<UserInfo> {
		// Select users using AEAD header.
		let cmd_keys_iter = self.users.iter().filter_map(|u| match &u.alter_ids {
			AlterId::Legacy(_) => None,
			AlterId::Aead => Some((&u.id, &u.cmd_key)),
		});
		let curr_time = timestamp_now();
		// Detect replay.
		if let Some(old_time) = self.container.insert(*auth_id, curr_time).await {
			error!(
				"auth_id already received at UNIX time {} (current: {})! This could be a replay attack!",
				old_time, curr_time,
			);
			return None;
		}
		if let Some((uuid, cmd_key, time)) = auth_id::check(auth_id, cmd_keys_iter) {
			let info = UserInfo {
				id: *uuid,
				cmd_key: *cmd_key,
				time,
			};
			if !is_recent(info.time, curr_time) {
				error!("auth_id outdated! This could be a replay attack.");
				return None;
			}
			trace!("Valid VMess AEAD request auth {:?}", auth_id);
			Some(info)
		} else {
			trace!("Invalid VMess AEAD request auth {:?}", auth_id);
			None
		}
	}

	#[inline]
	async fn get_user_from_auth(&self, auth: &AuthId) -> Option<(UserInfo, HeaderMode)> {
		self.check_auth_aead(auth)
			.await
			.map(|info| (info, HeaderMode::Aead))
	}
}

impl GetProtocolName for Settings {
	#[inline]
	fn protocol_name(&self) -> &'static str {
		super::PROTOCOL_NAME
	}
}

#[async_trait]
impl TcpAcceptor for Settings {
	#[inline]
	async fn accept_tcp<'a>(
		&'a self,
		mut stream: Box<dyn AsyncReadWrite>,
		_info: SessionInfo,
	) -> Result<AcceptResult<'a>, AcceptError> {
		debug!("Accepting VMess handshake");

		let mut auth_id = AuthId::default();
		stream.read_exact(&mut auth_id).await?;

		trace!("Checking client VMess auth_id");
		let (info, mode) = if let Some((info, mode)) = self.get_user_from_auth(&auth_id).await {
			(info, mode)
		} else {
			return invalid_request(stream, "invalid request auth for both legacy and AEAD");
		};

		let request = Request::decode(
			&mut stream,
			&info.id,
			&info.cmd_key,
			&auth_id,
			info.time,
			mode,
		)
		.await;
		let req = match request {
			Ok(req) => req,
			Err(err) => match err {
				ReadRequestError::Io(err) => {
					return Err(AcceptError::Io(err));
				}
				ReadRequestError::Invalid(err) => {
					return AcceptError::new_protocol_err(stream, err);
				}
			},
		};

		// create response cipher
		let (response_key, response_iv) =
			new_response_key_and_iv(&req.payload_key, &req.payload_iv, mode);

		let response = Response::new(req.v);
		let response_data = response.encode(&response_key, &response_iv, mode);

		let dst = req.dest_addr.clone();

		let algo = match req.sec {
			SecurityType::Chacha20Poly1305 => Some(Algorithm::ChaCha20Poly1305),
			SecurityType::Aes128Gcm => Some(Algorithm::Aes128Gcm),
			SecurityType::None => None,
			SecurityType::Zero => {
				// Zero cannot be used in request directly.
				// It only disables the chunk stream flag in request options.
				return invalid_request(stream, "'zero' cannot be used in request.");
			}
		};

		let cmd = req.cmd;
		let (r, w) = stream.split();

		#[allow(clippy::option_if_let_else)]
		let (r, w) = if let Some(algo) = algo {
			tcp::new_inbound_aead(
				r,
				w,
				algo,
				&req,
				&response_data,
				&response_key,
				&response_iv,
			)
		} else {
			tcp::new_inbound_plain(r, w, &req, response_data, &response_iv)
		};

		make_result(cmd, dst, r, w)
	}
}

#[inline]
fn invalid_request<T>(
	stream: Box<dyn AsyncReadWrite>,
	err: impl Into<Cow<'static, str>>,
) -> Result<T, AcceptError> {
	AcceptError::new_protocol_err(stream, Error::new_invalid_request(err))
}

#[derive(Clone)]
struct UserInfo {
	id: Uuid,
	cmd_key: [u8; 16],
	time: i64,
}

#[derive(Debug, Clone)]
pub struct User {
	id: Uuid,
	alter_ids: AlterId,
	cmd_key: [u8; 16],
}

impl User {
	#[inline]
	#[must_use]
	pub fn new(id: Uuid, num_alter_ids: usize) -> Self {
		let alter_ids = if num_alter_ids == 0 {
			AlterId::Aead
		} else {
			AlterId::Legacy(alter_ids::new(&id, num_alter_ids))
		};
		User {
			id,
			cmd_key: new_cmd_key(&id),
			alter_ids,
		}
	}

	#[must_use]
	pub fn uuid(&self) -> &Uuid {
		&self.id
	}
}

#[derive(Debug, Clone)]
enum AlterId {
	Aead,
	Legacy(Vec<Uuid>),
}

#[allow(clippy::unnecessary_wraps)]
fn make_result<'a, R, W>(
	cmd: Command,
	dst: SocksAddr,
	read_half: tcp::ReadHalf<R>,
	write_half: tcp::WriteHalf<W>,
) -> Result<AcceptResult<'a>, AcceptError>
where
	R: 'static + AsyncRead + Unpin + Send + Sync,
	W: 'static + AsyncWrite + Unpin + Send + Sync,
{
	match cmd {
		Command::Tcp => Ok(AcceptResult::Tcp(
			Box::new(PlainHandshakeHandler(BufBytesStream {
				r: read_half.into_boxed(),
				w: write_half.into_boxed(),
			})),
			dst,
		)),
		Command::Udp => {
			#[cfg(feature = "use-udp")]
			{
				let stream = udp::new_stream(read_half, write_half, dst);
				Ok(AcceptResult::Udp(stream))
			}
			#[cfg(not(feature = "use-udp"))]
			{
				Err(AcceptError::UdpNotAcceptable)
			}
		}
	}
}

/// Returns `true` if `time` is within `[curr_time - MAX_TIMESTAMP_DIFF, curr_time + MAX_TIMESTAMP_DIFF]`.
///
/// Returns `false` otherwise.
fn is_recent(time: i64, curr_time: i64) -> bool {
	let diff = u64::try_from((time - curr_time).abs()).unwrap();
	diff <= MAX_TIMESTAMP_DIFF
}

#[cfg(feature = "use_serde")]
mod serde_internals {
	use super::{User, Uuid};
	use serde::{Deserialize, Deserializer};

	#[derive(Deserialize)]
	#[serde(deny_unknown_fields)]
	pub struct SerdeUser {
		id: Uuid,
		#[serde(default)]
		num_alter_ids: usize,
	}

	impl<'de> Deserialize<'de> for User {
		fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
			let s = SerdeUser::deserialize(deserializer)?;
			Ok(User::new(s.id, s.num_alter_ids))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_partial_fmt_id() {
		let id = Uuid::from_str("a8963692-90e0-4897-8d71-dc1ce2d7fea6").unwrap();
		let output = PartialId(&id).to_string();
		assert_eq!(output.as_bytes(), b"a896");
	}

	#[test]
	fn test_display_info() {
		use crate::protocol::DisplayInfo;

		let s = SettingsBuilder {
			users: vec![
				User::new(
					Uuid::from_str("a8963692-90e0-4897-8d71-dc1ce2d7fea6").unwrap(),
					0,
				),
				User::new(
					Uuid::from_str("39c2f893-f167-4b09-abd4-f475dbb41e4f").unwrap(),
					0,
				),
				User::new(
					Uuid::from_str("f9d3ce5e-6014-4708-a882-7d4dd878e7a1").unwrap(),
					0,
				),
			],
		};
		assert_eq!(s.brief().to_string(), "vmess-in");
		assert_eq!(s.detail().to_string(), "vmess-in('a896*','39c2*','f9d3*')");
	}
}
