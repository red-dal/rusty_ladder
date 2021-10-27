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

macro_rules! impl_read {
	($dispatch:ident) => {
		fn poll_read(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
			buf: &mut ReadBuf<'_>,
		) -> Poll<std::io::Result<()>> {
			$dispatch!(self.get_mut(), Self, s, { Pin::new(s).poll_read(cx, buf) })
		}
	};
}

macro_rules! impl_write {
	($dispatch:ident) => {
		fn poll_write(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
			buf: &[u8],
		) -> Poll<Result<usize, std::io::Error>> {
			$dispatch!(self.get_mut(), Self, s, { Pin::new(s).poll_write(cx, buf) })
		}

		fn poll_flush(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
		) -> Poll<Result<(), std::io::Error>> {
			$dispatch!(self.get_mut(), Self, s, { Pin::new(s).poll_flush(cx) })
		}

		fn poll_shutdown(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
		) -> Poll<Result<(), std::io::Error>> {
			$dispatch!(self.get_mut(), Self, s, { Pin::new(s).poll_shutdown(cx) })
		}
	};
}
