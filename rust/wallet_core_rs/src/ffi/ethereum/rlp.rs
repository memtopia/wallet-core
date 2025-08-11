// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#![allow(clippy::missing_safety_doc)]

use tw_coin_registry::coin_type::CoinType;
use tw_coin_registry::dispatcher::evm_dispatcher;
use tw_memory::ffi::tw_data::TWData;
use tw_memory::ffi::RawPtrTrait;
use tw_misc::try_or_else;

/// Encodes an item or a list of items as Eth RLP binary format.
///
/// \param coin EVM-compatible coin type.
/// \param input Non-null serialized `EthereumRlp::Proto::EncodingInput`.
/// \return serialized `EthereumRlp::Proto::EncodingOutput`.
#[no_mangle]
pub unsafe extern "C" fn tw_ethereum_rlp_encode(coin: u32, input: *const TWData) -> *mut TWData {
    let coin = try_or_else!(CoinType::try_from(coin), std::ptr::null_mut);
    let input_data = try_or_else!(TWData::from_ptr_as_ref(input), std::ptr::null_mut);
    let evm_dispatcher = try_or_else!(evm_dispatcher(coin), std::ptr::null_mut);
    evm_dispatcher
        .encode_rlp(input_data.as_slice())
        .map(|data| TWData::from(data).into_ptr())
        .unwrap_or_else(|_| std::ptr::null_mut())
}

/// Decodes RLP encoded data to JSON format.
///
/// \param coin EVM-compatible coin type.
/// \param input Non-null serialized `EthereumRlp::Proto::DecodingInput`.
/// \return serialized `EthereumRlp::Proto::DecodingOutput`.
#[no_mangle]
pub unsafe extern "C" fn tw_ethereum_rlp_decode(coin: u32, input: *const TWData) -> *mut TWData {
    // Helper function to create error output proto
    let create_error_output = |error_msg: &str| -> *mut TWData {
        let error_output = tw_proto::EthereumRlp::Proto::DecodingOutput {
            json: std::borrow::Cow::from(error_msg),
            ..Default::default()
        };
        match tw_proto::serialize(&error_output) {
            Ok(serialized) => TWData::from(serialized).into_ptr(),
            Err(_) => {
                // Fallback: create a minimal error proto manually
                let fallback_error = tw_proto::EthereumRlp::Proto::DecodingOutput {
                    json: std::borrow::Cow::from("{\"error\": \"Proto serialization failed\"}"),
                    ..Default::default()
                };
                // Try serialization again, if this fails too, create minimal valid proto data
                match tw_proto::serialize(&fallback_error) {
                    Ok(data) => TWData::from(data).into_ptr(),
                    Err(_) => {
                        // Last resort: create manually crafted proto bytes for error message
                        // Proto field 1 (json) with value: {"error": "Critical proto failure"}
                        let manual_proto = b"\x0a\x23{\"error\": \"Critical proto failure\"}";
                        TWData::from(manual_proto.to_vec()).into_ptr()
                    }
                }
            }
        }
    };

    // Validate coin type
    let coin = match CoinType::try_from(coin) {
        Ok(c) => c,
        Err(_) => {
            return create_error_output(&format!("{{\"error\": \"Invalid coin type: {}\"}}", coin));
        }
    };
    
    // Validate input data pointer and handle empty data
    let input_data = match TWData::from_ptr_as_ref(input) {
        Some(data) => {
            if data.as_slice().is_empty() {
                return create_error_output("{\"error\": \"Empty proto data provided\"}");
            }
            data
        },
        None => {
            return create_error_output("{\"error\": \"Null input data pointer\"}");
        }
    };
    
    // Get EVM dispatcher
    let evm_dispatcher = match evm_dispatcher(coin) {
        Ok(dispatcher) => dispatcher,
        Err(e) => {
            return create_error_output(&format!("{{\"error\": \"No EVM dispatcher for coin type: {:?}, error: {:?}\"}}", coin, e));
        }
    };
    
    // Perform RLP decoding with enhanced error handling
    match evm_dispatcher.decode_rlp(input_data.as_slice()) {
        Ok(data) => TWData::from(data).into_ptr(),
        Err(e) => {
            let error_str = format!("{}", e);
            // Check if this is the specific deprecated group feature error
            if error_str.contains("Feature 'group' has been deprecated") {
                // This is a known issue with cryptographic libraries on iOS
                create_error_output("{\"error\": \"iOS_CRYPTO_COMPATIBILITY_ISSUE\", \"message\": \"This transaction type requires cryptographic features that are not fully compatible with the current iOS build. This is a known limitation that will be resolved in a future update.\", \"suggestion\": \"Try using a different transaction format or wait for a library update.\"}")
            } else {
                create_error_output(&format!("{{\"error\": \"EVM dispatcher decode failed: {}\"}}", error_str))
            }
        }
    }
}
