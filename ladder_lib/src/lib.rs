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

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
#![allow(clippy::default_trait_access)]

// TODO:
// - Balancer
// - Clean up trait

mod non_zeros;
mod prelude;
mod transport;
mod utils;

pub mod protocol;
pub mod proxy;
pub mod router;
pub mod server;
pub mod network;

#[cfg(test)]
mod test_utils;

pub use server::{stat::Monitor, BuildError as ServerBuildError, Builder as ServerBuilder, Server};
pub use utils::BytesCount;
