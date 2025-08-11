// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

use crate::address::Address;
use crate::rlp::buffer::RlpBuffer;
use crate::rlp::{RlpEncode, RlpDecode};
use tw_hash::H256;
use tw_number::U256;

impl RlpEncode for u8 {
    fn rlp_append(&self, buf: &mut RlpBuffer) {
        if *self == 0 {
            buf.append_data(&[])
        } else {
            buf.append_data(&[*self])
        }
    }
}

impl RlpEncode for U256 {
    fn rlp_append(&self, buf: &mut RlpBuffer) {
        buf.append_data(&self.to_big_endian_compact())
    }
}

impl RlpEncode for H256 {
    fn rlp_append(&self, buf: &mut RlpBuffer) {
        buf.append_data(self.as_slice())
    }
}

impl RlpEncode for Address {
    fn rlp_append(&self, buf: &mut RlpBuffer) {
        buf.append_data(self.as_slice())
    }
}

impl RlpEncode for Option<Address> {
    fn rlp_append(&self, buf: &mut RlpBuffer) {
        match self {
            Some(ref addr) => addr.rlp_append(buf),
            None => buf.append_data(&[]),
        }
    }
}

impl RlpEncode for [u8] {
    fn rlp_append(&self, buf: &mut RlpBuffer) {
        buf.append_data(self)
    }
}

impl RlpEncode for str {
    fn rlp_append(&self, buf: &mut RlpBuffer) {
        buf.append_data(self.as_bytes())
    }
}

// RlpDecode implementations
impl RlpDecode for u8 {
    fn rlp_decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let data = rlp.data()?;
        if data.is_empty() {
            Ok(0)
        } else if data.len() == 1 {
            Ok(data[0])
        } else {
            Err(rlp::DecoderError::RlpIncorrectListLen)
        }
    }
}

impl RlpDecode for U256 {
    fn rlp_decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let data = rlp.data()?;
        if data.is_empty() {
            Ok(U256::zero())
        } else {
            U256::from_big_endian_slice(data)
                .map_err(|_| rlp::DecoderError::Custom("Invalid U256"))
        }
    }
}

impl RlpDecode for H256 {
    fn rlp_decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let data = rlp.data()?;
        if data.len() != 32 {
            return Err(rlp::DecoderError::RlpIncorrectListLen);
        }
        Ok(H256::try_from(data).map_err(|_| rlp::DecoderError::Custom("Invalid H256"))?)
    }
}

impl RlpDecode for Address {
    fn rlp_decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let data = rlp.data()?;
        if data.len() != 20 {
            return Err(rlp::DecoderError::RlpIncorrectListLen);
        }
        Address::try_from(data).map_err(|_| rlp::DecoderError::Custom("Invalid Address"))
    }
}

impl RlpDecode for Option<Address> {
    fn rlp_decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let data = rlp.data()?;
        if data.is_empty() {
            Ok(None)
        } else if data.len() == 20 {
            Ok(Some(Address::try_from(data).map_err(|_| rlp::DecoderError::Custom("Invalid Address"))?))
        } else {
            Err(rlp::DecoderError::RlpIncorrectListLen)
        }
    }
}

impl RlpDecode for Vec<u8> {
    fn rlp_decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(rlp.data()?.to_vec())
    }
}
