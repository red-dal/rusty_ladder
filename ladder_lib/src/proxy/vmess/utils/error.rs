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

use super::super::Response;
use crate::{prelude::*, protocol::outbound::Error as OutboundError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("VMess invalid request ({0})")]
	InvalidRequest(Cow<'static, str>),
	#[error("VMess legacy stream encryption is not supported")]
	StreamEncryptionNotSupported,
	#[error("VMess invalid response {0:?}")]
	InvalidResponse(Response),
	#[error("VMess invalid crypto key length ({0})")]
	InvalidKeyLength(BoxStdErr),
	#[error("VMess invalid request ({0})")]
	FailedCrypto(BoxStdErr),
	#[error("zero security type cannot be used in UDP")]
	ZeroSecInUdp,
}

impl Error {
	#[inline]
	pub fn new_crypto(e: impl Into<BoxStdErr>) -> Self {
		Self::FailedCrypto(e.into())
	}

	#[inline]
	pub fn new_invalid_request<E>(details: E) -> Self
	where
		E: Into<Cow<'static, str>>,
	{
		Self::InvalidRequest(details.into())
	}
}

impl From<Error> for OutboundError {
	#[inline]
	fn from(e: Error) -> Self {
		OutboundError::Protocol(e.into())
	}
}
