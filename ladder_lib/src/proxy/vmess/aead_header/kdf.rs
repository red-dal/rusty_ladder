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

use core::cmp::min;
use hmac::{
	crypto_mac::{
		generic_array::{sequence::GenericSequence, GenericArray},
		Output,
	},
	digest::{BlockInput, Digest, FixedOutput},
	Mac,
};
use sha2::Sha256;
use std::convert::TryInto;

type HashType = Sha256;
type HashBlockSize = <HashType as BlockInput>::BlockSize;
type HashOutputSize = <HashType as FixedOutput>::OutputSize;

const VMESS_AEAD_KDF: &str = "VMess AEAD KDF";

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// KDF function for VMESS AEAD, returns the generated key.
///
/// See more at <https://github.com/v2fly/v2fly-github-io/issues/20>
fn kdf<'a>(key: &[u8], path: impl Iterator<Item = &'a [u8]>) -> [u8; 32] {
	let h: Box<dyn DynDigest> = Box::new(Sha256::new());
	let mut h: Box<dyn DynDigest> = Box::new(DynamicHmac::new(VMESS_AEAD_KDF.as_bytes(), h));
	for p in path {
		h = Box::new(DynamicHmac::new(p, h));
	}
	h.dyn_update(key);
	h.dyn_finialize_fixed_reset().into()
}

#[inline]
pub fn new_16<'a>(key: &[u8], path: impl Iterator<Item = &'a [u8]>) -> [u8; 16] {
	kdf(key, path)[..16].try_into().unwrap()
}

#[inline]
pub fn new_12<'a>(key: &[u8], path: impl Iterator<Item = &'a [u8]>) -> [u8; 12] {
	kdf(key, path)[..12].try_into().unwrap()
}

trait DynDigest {
	fn dyn_update(&mut self, data: &[u8]);
	fn dyn_reset(&mut self);
	fn dyn_finialize_fixed_reset(&mut self) -> GenericArray<u8, HashOutputSize>;
	fn clone_box(&self) -> Box<dyn DynDigest>;
}

impl Clone for Box<dyn DynDigest> {
	fn clone(&self) -> Self {
		self.clone_box()
	}
}

/// These codes are mostly copied from [`Hmac`] except the [`NewMac`] part.
///
/// [`Hmac`]: hmac::Hmac
/// [`NewMac`]: hmac::NewMac
#[derive(Clone)]
struct DynamicHmac {
	digest: Box<dyn DynDigest>,
	i_key_pad: GenericArray<u8, HashBlockSize>,
	opad_digest: Box<dyn DynDigest>,
}

impl DynamicHmac {
	#[inline]
	fn new(key: &[u8], basic_digest: Box<dyn DynDigest>) -> Self {
		let mut hmac = Self {
			digest: basic_digest.clone(),
			i_key_pad: GenericArray::generate(|_| IPAD),
			opad_digest: basic_digest,
		};

		let mut opad = GenericArray::<u8, HashBlockSize>::generate(|_| OPAD);
		debug_assert!(hmac.i_key_pad.len() == opad.len());

		// The key that Hmac processes must be the same as the block size of the
		// underlying Digest. If the provided key is smaller than that, we just
		// pad it with zeros. If its larger, we hash it and then pad it with
		// zeros.
		if key.len() <= hmac.i_key_pad.len() {
			for (k_idx, k_itm) in key.iter().enumerate() {
				hmac.i_key_pad[k_idx] ^= *k_itm;
				opad[k_idx] ^= *k_itm;
			}
		} else {
			let mut digest = hmac.digest.clone();
			digest.dyn_update(key);
			let output = digest.dyn_finialize_fixed_reset();
			// `n` is calculated at compile time and will equal
			// D::OutputSize. This is used to ensure panic-free code
			let n = min(output.len(), hmac.i_key_pad.len());
			for idx in 0..n {
				hmac.i_key_pad[idx] ^= output[idx];
				opad[idx] ^= output[idx];
			}
		}

		hmac.digest.dyn_update(&hmac.i_key_pad);
		hmac.opad_digest.dyn_update(&opad);

		hmac
	}
}

impl Mac for DynamicHmac {
	type OutputSize = HashOutputSize;

	#[inline]
	fn update(&mut self, data: &[u8]) {
		self.digest.dyn_update(data);
	}

	#[inline]
	fn finalize(mut self) -> Output<Self> {
		let mut opad_digest = self.opad_digest.clone();
		let hash = self.digest.dyn_finialize_fixed_reset();
		opad_digest.dyn_update(&hash);
		Output::new(opad_digest.dyn_finialize_fixed_reset())
	}

	#[inline]
	fn reset(&mut self) {
		self.digest.dyn_reset();
		self.digest.dyn_update(&self.i_key_pad);
	}
}

impl DynDigest for DynamicHmac {
	fn dyn_update(&mut self, data: &[u8]) {
		Mac::update(self, data);
	}

	fn dyn_reset(&mut self) {
		Mac::reset(self);
	}

	fn dyn_finialize_fixed_reset(&mut self) -> GenericArray<u8, HashOutputSize> {
		Mac::finalize_reset(self).into_bytes()
	}

	fn clone_box(&self) -> Box<dyn DynDigest> {
		Box::new(self.clone())
	}
}

impl DynDigest for Sha256 {
	fn dyn_update(&mut self, data: &[u8]) {
		Digest::update(self, data);
	}

	fn dyn_reset(&mut self) {
		Digest::reset(self);
	}

	fn dyn_finialize_fixed_reset(&mut self) -> GenericArray<u8, HashOutputSize> {
		Digest::finalize_reset(self)
	}

	fn clone_box(&self) -> Box<dyn DynDigest> {
		Box::new(self.clone())
	}
}

#[cfg(test)]
mod tests {
	use super::Digest;
	use super::*;
	use hmac::{Hmac, NewMac};

	#[test]
	fn test_dynamic_hmac() {
		// test MyDigest
		{
			let data = b"This is some more data";
			let expected = {
				let mut h = Sha256::default();
				Digest::update(&mut h, data);
				h.finalize()
			};
			let result = {
				let mut h: Box<dyn DynDigest> = Box::new(Sha256::default());
				h.dyn_update(data);
				h.dyn_finialize_fixed_reset()
			};

			assert_eq!(expected, result);
		}

		let data = b"This is some data";
		let input_key = b"Hello this is an input key";
		let expected = {
			type HmacSha256 = Hmac<Sha256>;
			let mut h = HmacSha256::new_from_slice(input_key).unwrap();
			h.update(data);
			h.finalize().into_bytes()
		};

		let result = {
			let h = Sha256::default();
			let mut h = DynamicHmac::new(input_key, Box::new(h));
			h.update(data);
			h.finalize().into_bytes()
		};

		assert_eq!(result, expected);
	}

	#[test]
	fn test_kdf() {
		let expected = [
			102, 228, 26, 212, 127, 167, 69, 251, 253, 30, 151, 50, 94, 147, 219, 244, 160, 77,
			170, 192, 62, 80, 253, 243, 5, 45, 167, 19, 102, 98, 223, 225,
		];
		let test_key = b"Demo Key for Auth ID Test";
		let test_path = [b"Demo Path for Auth ID Test"];

		let res = kdf(test_key, test_path.iter().map(|x| x.as_ref()));

		assert_eq!(res, expected);
	}
}
