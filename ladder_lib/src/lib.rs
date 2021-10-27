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

// TODO:
// - Balancer
// - Clean up trait

/// Some common non zero values that needs unsafe to initialize.
/// Use value here to avoid using unwrap.
mod non_zeros;

// All codes below forbid unsafe.

#[forbid(unsafe_code)]
mod prelude;
#[forbid(unsafe_code)]
pub mod protocol;
#[forbid(unsafe_code)]
pub mod proxy;
#[forbid(unsafe_code)]
pub mod router;
#[forbid(unsafe_code)]
pub mod server;
#[cfg(test)]
#[forbid(unsafe_code)]
mod test_utils;
#[forbid(unsafe_code)]
mod transport;
#[forbid(unsafe_code)]
mod utils;

pub use server::{stat::Monitor, BuildError as ServerBuildError, Builder as ServerBuilder, Server};
pub use utils::BytesCount;
