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
use super::super::{
	response::{open_len, open_payload},
	utils::{
		aead_codec, generate_chacha20_key, new_response_key_and_iv, plain_codec, Error,
		ShakeLengthReader, ShakeLengthWriter,
	},
	Request, Response, MAX_PAYLOAD_LENGTH,
};
use super::HeaderMode;
use crate::{
	prelude::*,
	protocol::{outbound::Error as OutboundError, BufBytesStream},
	utils::{
		codec::{Decode, Encode, FrameReadHalf, FrameWriteHalf},
		crypto::aead::{Algorithm, Decrypt, Decryptor, Encrypt, Encryptor, Key as AeadKey},
		poll_read_exact, LazyWriteHalf,
	},
};
use futures::ready;
use std::{
	io,
	pin::Pin,
	task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, ReadBuf};
use uuid::Uuid;

type VMessKey = [u8; 16];
type VMessIv = [u8; 16];

enum ReadResponseState {
	ReadingResponseAeadLen { pos: usize },
	ReadingResponseAeadPayload { pos: usize },
	Done,
}

struct ResponseHelper {
	response_key: VMessKey,
	response_iv: VMessIv,
	req: Request,
	state: ReadResponseState,
}

impl ResponseHelper {
	/// Attempts to read a response from `r` and check if it's valid.
	///
	/// Returns `Poll::Ready(Ok(()))` if a response is successfully read.
	///
	/// Returns `Poll::Ready(Err(err))` if there is IO error, invalid response or invalid user.
	///
	/// If a `Poll::Ready` has been returned, trying to call this function will only return
	/// `Poll::Ready(Ok(()))`.
	fn poll_read_response<R>(
		&mut self,
		mut r: Pin<&mut R>,
		cx: &mut Context,
		buf: &mut Vec<u8>,
	) -> Poll<io::Result<()>>
	where
		R: AsyncRead,
	{
		// `state` must start with ReadingResponseLegacy or ReadingResponseAeadLen.
		//
		// Starting with ReadingResponseLegacy means reading a legacy response.
		// Legacy response is deprecated, please use AEAD instead.
		//
		// Starting with ReadingResponseAeadLen means reading an AEAD response.
		//
		// For more info about AEAD response, check out
		// https://github.com/v2fly/v2fly-github-io/issues/20

		// State graph:
		//
		// +-------------------------+        read/check done/err          +------+
		// | Reading response legacy | ----------------------------------->| Done |
		// +-------------------------+                                     +------+
		//                                                                     ^
		//                                                                     |
		//           +---------------------------------------------------------+
		//           |                                                         |
		//           |                                                         |
		//           |read err                                                 |
		//           |                                                         | read/check done/err
		//           |                                                         |
		// +---------------------+          read done         +----------------------+
		// | Reading AEAD length | ---- (payload length) ---->| Reading AEAD payload |
		// +---------------------+                            +----------------------+
		#[inline]
		fn eof<T>(msg: &str) -> Poll<Result<T, io::Error>> {
			Poll::Ready(Err(io::Error::new(
				io::ErrorKind::UnexpectedEof,
				msg.to_owned(),
			)))
		}
		loop {
			match &mut self.state {
				ReadResponseState::ReadingResponseAeadLen { pos } => {
					buf.resize(18, 0);
					// 2 bytes (u16) + 16 bytes (TAG)
					debug_assert_eq!(buf.len(), 18);
					let n = ready!(poll_read_exact(r.as_mut(), cx, buf, pos))?;
					trace!("VMess response length done reading, n: {}", n);
					if n == 0 {
						self.state = ReadResponseState::Done;
						return eof("cannot read VMess AEAD response length because of EOF");
					}
					let len =
						open_len(buf, &self.response_key, &self.response_iv).map_err(|e| {
							io::Error::new(
								io::ErrorKind::InvalidData,
								format!("cannot decrypt VMess AEAD response ({})", e),
							)
						})?;
					trace!("VMess AEAD payload length: {}", len);
					if len == 0 {
						// length buffer is empty, EOF
						self.state = ReadResponseState::Done;
						return eof("VMess response length is zero");
					}
					// dont forget the tag
					buf.resize(len + 16, 0);
					self.state = ReadResponseState::ReadingResponseAeadPayload { pos: 0 };
				}
				ReadResponseState::ReadingResponseAeadPayload { pos } => {
					debug_assert!(buf.len() > 16);
					let n = ready!(poll_read_exact(r.as_mut(), cx, buf, pos))?;

					if n == 0 {
						self.state = ReadResponseState::Done;
						return eof("cannot read VMess AEAD response payload because of EOF");
					}

					let buf = open_payload(buf, &self.response_key, &self.response_iv)
						.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

					let response = Response::parse(buf);
					trace!("AEAD response received: {:?}", response);

					if self.req.v == response.v {
						self.state = ReadResponseState::Done;
					} else {
						return Err(io::Error::new(
							io::ErrorKind::InvalidData,
							Error::InvalidResponse(response),
						))
						.into();
					}
				}
				ReadResponseState::Done => {
					return Ok(()).into();
				}
			}
		}
	}
}

enum ReadHalfState {
	ReadingResponse {
		response_reader: ResponseHelper,
		buf: Vec<u8>,
	},
	Reading,
	Closed,
}

impl ReadHalfState {
	#[inline]
	fn new(
		response_key: VMessKey,
		response_iv: VMessIv,
		req: Request,
		state: ReadResponseState,
	) -> Self {
		ReadHalfState::ReadingResponse {
			response_reader: ResponseHelper {
				response_key,
				response_iv,
				req,
				state,
			},
			buf: Vec::new(),
		}
	}

	#[inline]
	pub fn new_aead(response_key: VMessKey, response_iv: VMessIv, req: Request) -> Self {
		Self::new(
			response_key,
			response_iv,
			req,
			ReadResponseState::ReadingResponseAeadLen { pos: 0 },
		)
	}
}

pub struct ReadHalf<R, D>
where
	R: AsyncRead + Unpin,
	D: Decode,
{
	fr: FrameReadHalf<D, R>,
	state: ReadHalfState,
}

impl<R, D> ReadHalf<R, D>
where
	R: AsyncRead + Unpin,
	D: Decode,
{
	pub fn new_aead(
		r: R,
		dec: D,
		response_key: VMessKey,
		response_iv: VMessIv,
		req: Request,
	) -> Self {
		Self {
			state: ReadHalfState::new_aead(response_key, response_iv, req),
			fr: FrameReadHalf::new(dec, r),
		}
	}
}

impl<R, D> AsyncRead for ReadHalf<R, D>
where
	R: AsyncRead + Unpin,
	D: Decode,
{
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		read_buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let data = ready!(self.as_mut().poll_fill_buf(cx))?;
		let amt = std::cmp::min(data.len(), read_buf.remaining());
		read_buf.put_slice(&data[..amt]);
		self.as_mut().consume(amt);
		Ok(()).into()
	}
}

impl<R, D> AsyncBufRead for ReadHalf<R, D>
where
	R: AsyncRead + Unpin,
	D: Decode,
{
	fn poll_fill_buf<'a>(
		self: Pin<&'a mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<io::Result<&'a [u8]>> {
		let me = self.get_mut();
		loop {
			match &mut me.state {
				// First try to read response from  server.
				ReadHalfState::ReadingResponse {
					response_reader: reader,
					buf,
				} => {
					if let Err(e) =
						ready!(reader.poll_read_response(Pin::new(&mut me.fr.r), cx, buf))
					{
						me.state = ReadHalfState::Closed;
						return Err(e).into();
					}
					trace!("Done reading VMess response");
					me.state = ReadHalfState::Reading;
				}
				// Buffering
				ReadHalfState::Reading => {
					let data = match ready!(Pin::new(&mut me.fr).poll_fill_buf(cx)) {
						Ok(data) => data,
						Err(e) => {
							me.state = ReadHalfState::Closed;
							return Err(e).into();
						},
					};
					if data.is_empty() {
						// EOF
						me.state = ReadHalfState::Closed;
						trace!("ReadHalf's FrameReadHalf reached EOF");
					}
					return Ok(data).into();
				}
				ReadHalfState::Closed => {
					return Err(io::Error::new(
						io::ErrorKind::BrokenPipe,
						"VMess read half already closed",
					))
					.into();
				}
			}
		}
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		if let ReadHalfState::Reading = &self.state {
			Pin::new(&mut self.get_mut().fr).consume(amt);
		} else {
			panic!("consume can only be called in ReadHalfState::Reading");
		}
	}
}

struct ChunkStreamArgs<'a, R, W, E, D> {
	pub r: R,
	pub w: W,
	pub dec: D,
	pub enc: E,
	pub req: Request,
	pub response_key: &'a [u8; 16],
	pub response_iv: &'a [u8; 16],
	pub mode: HeaderMode,
}

impl<R, W, E, D> ChunkStreamArgs<'_, R, W, E, D>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
	E: Encode,
	D: Decode,
{
	fn build(self) -> (ReadHalf<R, D>, FrameWriteHalf<E, W>)
	where
		R: AsyncRead + Unpin,
		W: AsyncWrite + Unpin,
		E: Encode,
		D: Decode,
	{
		let read_half = {
			match self.mode {
				HeaderMode::Aead => ReadHalf::new_aead(
					self.r,
					self.dec,
					*self.response_key,
					*self.response_iv,
					self.req,
				),
			}
		};

		(
			read_half,
			FrameWriteHalf::new(MAX_PAYLOAD_LENGTH, self.enc, self.w),
		)
	}
}

pub enum PlainStream<R, W>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	Masking(
		(
			ReadHalf<R, plain_codec::ShakeLenDecoder>,
			FrameWriteHalf<plain_codec::ShakeLenEncoder, W>,
		),
	),
	NoMasking(
		(
			ReadHalf<R, plain_codec::PlainLenDecoder>,
			FrameWriteHalf<plain_codec::PlainLenEncoder, W>,
		),
	),
}

impl<R, W> From<PlainStream<R, W>> for BufBytesStream
where
	R: 'static + AsyncRead + Unpin + Send + Sync,
	W: 'static + AsyncWrite + Unpin + Send + Sync,
{
	fn from(s: PlainStream<R, W>) -> Self {
		match s {
			PlainStream::Masking((r, w)) => BufBytesStream::new(Box::new(r), Box::new(w)),
			PlainStream::NoMasking((r, w)) => BufBytesStream::new(Box::new(r), Box::new(w)),
		}
	}
}

mod plain_internal {
	use super::{AsyncRead, AsyncWrite, Context, Pin, PlainStream, Poll, ReadBuf};

	macro_rules! dispatch_plain_read {
	($stream:expr, $enum_name:ident, $with:ident, $func:tt) => {{
		match $stream {
			$enum_name::Masking(($with, _)) => $func
			$enum_name::NoMasking(($with, _)) => $func
			}
		}};
	}

	macro_rules! dispatch_plain_write {
		($stream:expr, $enum_name:ident, $with:ident, $func:tt) => {{
			match $stream {
				$enum_name::Masking((_, $with)) => $func
				$enum_name::NoMasking((_, $with)) => $func
				}
			}};
		}

	impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for PlainStream<R, W> {
		impl_read!(dispatch_plain_read);
	}

	impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for PlainStream<R, W> {
		impl_write!(dispatch_plain_write);
	}
}

/// Read half for 'zero' mode.
pub struct ZeroReadHalf<R>
where
	R: AsyncRead + Unpin,
{
	r: R,
	state: Option<(ResponseHelper, Vec<u8>)>,
}

impl<R> ZeroReadHalf<R> where R: AsyncRead + Unpin {}

impl<R> AsyncRead for ZeroReadHalf<R>
where
	R: AsyncRead + Unpin,
{
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let me = self.get_mut();
		if let Some((helper, buf)) = &mut me.state {
			ready!(helper.poll_read_response(Pin::new(&mut me.r), cx, buf))?;
			me.state = None;
		}
		Pin::new(&mut me.r).poll_read(cx, buf)
	}
}

pub(super) fn new_outbound_zero<R, W>(
	r: R,
	w: W,
	req: Request,
	id: &Uuid,
	time: i64,
	mode: HeaderMode,
) -> (ZeroReadHalf<R>, LazyWriteHalf<W>)
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let (response_key, response_iv) =
		new_response_key_and_iv(&req.payload_key, &req.payload_iv, mode);

	let (request_data, state) = match mode {
		HeaderMode::Aead => (
			req.encode_aead(id, time),
			ReadResponseState::ReadingResponseAeadLen { pos: 0 },
		),
	};

	let w = LazyWriteHalf::new(w, request_data);
	let r = ZeroReadHalf {
		r,
		state: Some((
			ResponseHelper {
				response_key,
				response_iv,
				req,
				state,
			},
			Vec::new(),
		)),
	};
	(r, w)
}

/// Create a new plain stream with no encryption.
///
/// # Panics
///
/// Panics if `req.opt.chunk_stream()` is false.
pub(super) fn new_outbound_plain<R, W>(
	r: R,
	w: W,
	req: Request,
	id: &Uuid,
	time: i64,
	mode: HeaderMode,
) -> PlainStream<R, W>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let (response_key, response_iv) =
		new_response_key_and_iv(&req.payload_key, &req.payload_iv, mode);

	let request_data = match mode {
		HeaderMode::Aead => req.encode_aead(id, time),
	};

	assert!(req.opt.chunk_stream());

	if req.opt.chunk_masking() {
		let writer_iv = &req.payload_iv;
		let reader_iv = &response_iv;
		let use_padding = req.opt.global_padding();

		let (r, mut w) = ChunkStreamArgs {
			r,
			w,
			enc: plain_codec::new_shake_enc(writer_iv, use_padding),
			dec: plain_codec::new_shake_dec(reader_iv, use_padding),
			req,
			response_key: &response_key,
			response_iv: &response_iv,
			mode,
		}
		.build();
		w.encoder.lazy_buf.put_slice(&request_data);
		PlainStream::Masking((r, w))
	} else {
		let (r, mut w) = ChunkStreamArgs {
			r,
			w,
			enc: plain_codec::new_plain_enc(),
			dec: plain_codec::new_plain_dec(),
			req,
			response_key: &response_key,
			response_iv: &response_iv,
			mode,
		}
		.build();
		w.encoder.lazy_buf.put_slice(&request_data);
		PlainStream::NoMasking((r, w))
	}
}

pub type AeadReadHalf<R> = ReadHalf<R, aead_codec::Decoder<ShakeLengthReader>>;
pub type AeadWriteHalf<W> = FrameWriteHalf<aead_codec::Encoder<ShakeLengthWriter>, W>;

pub(super) fn new_outbound_aead<R, W>(
	r: R,
	w: W,
	req: Request,
	id: &Uuid,
	time: i64,
	algo: Algorithm,
	mode: HeaderMode,
) -> Result<(AeadReadHalf<R>, AeadWriteHalf<W>), OutboundError>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	if !(req.opt.chunk_stream() && req.opt.chunk_masking()) {
		// chunk stream and masking must both be enabled
		let err = Error::new_invalid_request(
            "Programming error, encrypted stream's request must have both chunk stream and chunk masking options enabled",
        );
		return Err(OutboundError::Protocol(err.into()));
	}

	let use_padding = req.opt.global_padding();
	let (response_key, response_iv) =
		new_response_key_and_iv(&req.payload_key, &req.payload_iv, mode);

	let encoder = {
		let writer_key = &req.payload_key;
		let writer_iv = &req.payload_iv;
		let encryptor = if let Algorithm::ChaCha20Poly1305 = algo {
			let mut chacha_key = [0_u8; 32];
			generate_chacha20_key(writer_key, &mut chacha_key);
			Encryptor::new_encryptor(
				AeadKey::ChaCha20Poly1305(chacha_key),
				aead_codec::VmessNonceSequence::new(writer_iv),
			)
			.map_err(Error::new_crypto)?
		} else {
			Encryptor::new_encryptor(
				AeadKey::Aes128Gcm(req.payload_key),
				aead_codec::VmessNonceSequence::new(writer_iv),
			)
			.map_err(Error::new_crypto)?
		};
		aead_codec::Encoder::new(encryptor, ShakeLengthWriter::new(writer_iv, use_padding))
	};

	let decoder = {
		let reader_key = &response_key;
		let reader_iv = &response_iv;
		let decryptor = if let Algorithm::ChaCha20Poly1305 = algo {
			let mut chacha_key = [0_u8; 32];
			generate_chacha20_key(reader_key, &mut chacha_key);
			Decryptor::new_decryptor(
				AeadKey::ChaCha20Poly1305(chacha_key),
				aead_codec::VmessNonceSequence::new(reader_iv),
			)
			.map_err(Error::new_crypto)?
		} else {
			Decryptor::new_decryptor(
				AeadKey::Aes128Gcm(*reader_key),
				aead_codec::VmessNonceSequence::new(reader_iv),
			)
			.map_err(Error::new_crypto)?
		};
		aead_codec::Decoder::new(
			decryptor,
			ShakeLengthReader::new(reader_iv, req.opt.global_padding()),
		)
	};

	let request_data = match mode {
		HeaderMode::Aead => req.encode_aead(id, time),
	};

	let (r, mut w) = ChunkStreamArgs {
		r,
		w,
		dec: decoder,
		enc: encoder,
		req,
		response_key: &response_key,
		response_iv: &response_iv,
		mode,
	}
	.build();
	w.encoder.lazy_buf.put_slice(&request_data);
	Ok((r, w))
}
