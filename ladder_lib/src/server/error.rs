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

use crate::{
	prelude::{BoxStdErr, Tag},
	protocol::{inbound, outbound}, router,
};
use std::io;
use thiserror::Error as ThisError;
use std::borrow::Cow;

#[derive(Debug, ThisError)]
pub enum Server {
	#[error("proxy outbound error ({0})")]
	Outbound(#[from] outbound::Error),
	#[error("proxy inbound error ({0})")]
	Inbound(#[from] inbound::HandshakeError),
	#[error("proxy IO error ({0})")]
	Io(#[from] io::Error),
    #[error("inactive for {0} secs")]
    Inactive(usize),
	#[error("proxy error ({0})")]
	Other(BoxStdErr),
}

#[derive(Debug, thiserror::Error)]
pub enum Building {
	#[error("tag '{tag}' on inbound '{ind}' already exists")]
	InboundTagAlreadyExists { ind: usize, tag: Tag },
	#[error("tag '{tag}' on outbound '{ind}' already exists")]
	OutboundTagAlreadyExists { ind: usize, tag: Tag },
	#[error("error on inbound '{ind}' ({err})")]
	Inbound { ind: usize, err: BoxStdErr },
	#[error("error on outbound '{ind}' ({err})")]
	Outbound { ind: usize, err: BoxStdErr },
	#[error("router error ({0})")]
	Router(#[from] router::Error),
	#[error("api error ({0})")]
	Api(BoxStdErr),
	#[error("value of '{0}' cannot be zero")]
	ValueIsZero(Cow<'static, str>),
}
