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
	utils::{aead_codec, generate_chacha20_key, plain_codec, ShakeLengthReader},
	MAX_PAYLOAD_LENGTH,
};
use super::Request;
use crate::{
	prelude::*,
	protocol::{BoxBufRead, BoxWrite},
	proxy::vmess::utils::ShakeLengthWriter,
	utils::{
		codec::{Decode, Encode, FrameReadHalf, FrameWriteHalf},
		crypto::aead::{Algorithm, Decrypt, Decryptor, Encrypt, Encryptor, Key},
		LazyWriteHalf,
	},
};
use std::{
	pin::Pin,
	task::{Context, Poll},
};
use tokio::io::ReadBuf;

struct ChunkStreamArgs<R, W, D, E> {
	r: R,
	w: W,
	decoder: D,
	encoder: E,
}

fn new_chunk_stream<R, W, D, E>(
	args: ChunkStreamArgs<R, W, D, E>,
) -> (FrameReadHalf<D, R>, FrameWriteHalf<E, W>)
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
	D: 'static + Decode,
	E: 'static + Encode,
{
	let w = FrameWriteHalf::new(MAX_PAYLOAD_LENGTH, args.encoder, args.w);
	let r = FrameReadHalf::new(args.decoder, args.r);

	(r, w)
}

macro_rules! dispatch {
	($t:expr, $enum_name:ident, $r:ident, $body:tt) => {
		match $t {
			$enum_name::Plain($r) => $body
			$enum_name::PlainChunk($r) => $body
			$enum_name::PlainChunkMask($r) => $body
			$enum_name::Aead($r) => $body
		}
	};
}

pub enum ReadHalf<R: AsyncRead + Unpin> {
	Plain(R),
	PlainChunk(FrameReadHalf<plain_codec::PlainLenDecoder, R>),
	PlainChunkMask(FrameReadHalf<plain_codec::ShakeLenDecoder, R>),
	Aead(FrameReadHalf<aead_codec::Decoder<ShakeLengthReader>, R>),
}

impl<R: 'static + AsyncRead + Unpin + Send + Sync> ReadHalf<R> {
	pub fn into_boxed(self) -> BoxBufRead {
		match self {
			ReadHalf::Plain(r) => Box::new(tokio::io::BufReader::new(r)),
			ReadHalf::PlainChunk(r) => Box::new(r),
			ReadHalf::PlainChunkMask(r) => Box::new(r),
			ReadHalf::Aead(r) => Box::new(r),
		}
	}
}

impl<R: AsyncRead + Unpin> AsyncRead for ReadHalf<R> {
	impl_read!(dispatch);
}

pub enum WriteHalf<W: AsyncWrite + Unpin> {
	Plain(LazyWriteHalf<W>),
	PlainChunk(FrameWriteHalf<plain_codec::PlainLenEncoder, W>),
	PlainChunkMask(FrameWriteHalf<plain_codec::ShakeLenEncoder, W>),
	Aead(FrameWriteHalf<aead_codec::Encoder<ShakeLengthWriter>, W>),
}

impl<W: 'static + AsyncWrite + Unpin + Send + Sync> WriteHalf<W> {
	pub fn into_boxed(self) -> BoxWrite {
		dispatch!(self, Self, r, { Box::new(r) })
	}
}

impl<W: AsyncWrite + Unpin> AsyncWrite for WriteHalf<W> {
	impl_write!(dispatch);
}

pub fn new_inbound_plain<R, W>(
	r: R,
	w: W,
	req: &Request,
	response_data: Vec<u8>,
	response_iv: &[u8; 16],
) -> (ReadHalf<R>, WriteHalf<W>)
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	if req.opt.chunk_stream() {
		trace!("Creating VMess chunk stream.");
		if req.opt.chunk_masking() {
			let writer_iv = response_iv;
			let encoder = plain_codec::new_shake_enc(writer_iv, req.opt.global_padding());

			let reader_iv = &req.payload_iv;
			let decoder = plain_codec::new_shake_dec(reader_iv, req.opt.global_padding());

			// chunk stream with length masking
			let (r, mut w) = new_chunk_stream(ChunkStreamArgs {
				r,
				w,
				decoder,
				encoder,
			});
			w.encoder.lazy_buf.put_slice(&response_data);
			(ReadHalf::PlainChunkMask(r), WriteHalf::PlainChunkMask(w))
		} else {
			// chunk stream
			let (r, mut w) = new_chunk_stream(ChunkStreamArgs {
				r,
				w,
				decoder: plain_codec::new_plain_dec(),
				encoder: plain_codec::new_plain_enc(),
			});
			w.encoder.lazy_buf.put_slice(&response_data);
			(ReadHalf::PlainChunk(r), WriteHalf::PlainChunk(w))
		}
	} else {
		// Write response data first.
		trace!("Creating VMess zero stream.");
		let w = LazyWriteHalf::new(w, response_data);
		(ReadHalf::Plain(r), WriteHalf::Plain(w))
	}
}

pub fn new_inbound_aead<R, W>(
	read_half: R,
	write_half: W,
	algo: Algorithm,
	request: &Request,
	response_data: &[u8],
	response_key: &[u8; 16],
	response_iv: &[u8; 16],
) -> (ReadHalf<R>, WriteHalf<W>)
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let writer_key = response_key;
	let writer_iv = response_iv;
	// writer
	// Writer part use payload key and iv.
	// The official document is wrong about this.
	let enc = if Algorithm::ChaCha20Poly1305 == algo {
		let mut chacha_key = [0_u8; 32];
		generate_chacha20_key(writer_key, &mut chacha_key);
		Encryptor::new_encryptor(
			Key::ChaCha20Poly1305(chacha_key),
			aead_codec::VmessNonceSequence::new(writer_iv),
		)
		.expect("Programming error: invalid vmess inbound AeadEncryptor key size")
	} else {
		Encryptor::new_encryptor(
			Key::Aes128Gcm(*writer_key),
			aead_codec::VmessNonceSequence::new(writer_iv),
		)
		.expect("Programming error: invalid vmess inbound AeadEncryptor key size")
	};
	let encoder = aead_codec::Encoder::new(
		enc,
		ShakeLengthWriter::new(writer_iv, request.opt.global_padding()),
	);

	let reader_key = &request.payload_key;
	let reader_iv = &request.payload_iv;
	// reader
	// Reader part use response key and iv.
	// The official document is wrong about this.
	let dec = if Algorithm::ChaCha20Poly1305 == algo {
		let mut chacha_key = [0_u8; 32];
		generate_chacha20_key(reader_key, &mut chacha_key);
		Decryptor::new_decryptor(
			Key::ChaCha20Poly1305(chacha_key),
			aead_codec::VmessNonceSequence::new(reader_iv),
		)
		.expect("Programming error: invalid vmess inbound AeadDecryptor key size")
	} else {
		Decryptor::new_decryptor(
			Key::Aes128Gcm(*reader_key),
			aead_codec::VmessNonceSequence::new(reader_iv),
		)
		.expect("Programming error: invalid vmess inbound AeadDecryptor key size")
	};
	let decoder = aead_codec::Decoder::new(
		dec,
		ShakeLengthReader::new(reader_iv, request.opt.global_padding()),
	);

	let (r, mut w) = new_chunk_stream(ChunkStreamArgs {
		r: read_half,
		w: write_half,
		decoder,
		encoder,
	});
	w.encoder.lazy_buf.put_slice(response_data);
	(ReadHalf::Aead(r), WriteHalf::Aead(w))
}
