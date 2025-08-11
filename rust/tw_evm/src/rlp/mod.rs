// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

use crate::rlp::buffer::RlpBuffer;

pub mod buffer;
pub mod impls;
pub mod list;

/// The trait should be implemented for all types that need to be encoded in RLP.
pub trait RlpEncode {
    fn rlp_append(&self, buf: &mut RlpBuffer);
}

/// The trait should be implemented for all types that need to be decoded from RLP.
pub trait RlpDecode: Sized {
    fn rlp_decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError>;
}
