// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

use crate::evm_context::EvmContext;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::marker::PhantomData;
use tw_coin_entry::error::prelude::*;
use tw_encoding::hex;
use tw_number::U256;
use tw_proto::EthereumRlp::Proto;

/// cbindgen:ignore
pub const RECURSION_LIMIT: usize = 10;

pub struct RlpDecoder<Context: EvmContext> {
    _phantom: PhantomData<Context>,
}

impl<Context: EvmContext> RlpDecoder<Context> {
    pub fn decode_with_proto(input: Proto::DecodingInput<'_>) -> Proto::DecodingOutput<'static> {
        Self::decode_with_proto_impl(input)
            .unwrap_or_else(|e| {
                let error_str = format!("{}", e);
                // Check for the specific cryptographic library deprecation issue
                let error_json = if error_str.contains("Feature 'group' has been deprecated") {
                    "{\"error\": \"iOS_CRYPTO_COMPATIBILITY_ISSUE\", \"message\": \"Unable to decode this transaction type due to iOS cryptographic library limitations.\"}".to_string()
                } else {
                    format!("{{\"error\": \"RLP decode failed: {}\"}}", error_str)
                };
                
                Proto::DecodingOutput {
                    json: Cow::from(error_json),
                    ..Proto::DecodingOutput::default()
                }
            })
    }

    fn decode_with_proto_impl(
        input: Proto::DecodingInput<'_>,
    ) -> SigningResult<Proto::DecodingOutput<'static>> {
        if input.encoded.is_empty() {
            return SigningError::err(SigningErrorType::Error_invalid_params)
                .context("No RLP data provided - input.encoded is empty");
        }

        let data = input.encoded.as_ref();
        
        // Check if this might be an EVM transaction with type prefix
        let decoded_json_value = if data.len() > 1 && data[0] < 0x7f {
            // This looks like a typed transaction (EIP-2718)
            let tx_type = data[0];
            let rlp_data = &data[1..];
            let rlp = rlp::Rlp::new(rlp_data);
            
            // Decode as structured transaction
            Self::decode_transaction(tx_type, &rlp)?
        } else {
            // This is either a legacy transaction or regular RLP data
            let rlp = rlp::Rlp::new(data);
            
            // Check if it's a legacy transaction (should be a list with 9+ items)
            if rlp.is_list() && rlp.item_count().unwrap_or(0) >= 9 {
                Self::decode_transaction(0, &rlp)? // Legacy transaction (type 0)
            } else {
                // Regular RLP data
                let initial_depth = 0;
                Self::decode_rlp_to_json(initial_depth, &rlp)?
            }
        };
        
        let json_string = serde_json::to_string(&decoded_json_value)
            .map_err(|e| SigningError::from(SigningErrorType::Error_internal)
                .context(format!("Failed to serialize to JSON: {}", e)))?;

        Ok(Proto::DecodingOutput {
            json: Cow::from(json_string),
            ..Proto::DecodingOutput::default()
        })
    }

    fn decode_rlp_to_json(depth: usize, rlp: &rlp::Rlp) -> SigningResult<Value> {
        if depth >= RECURSION_LIMIT {
            return SigningError::err(SigningErrorType::Error_invalid_params).with_context(|| {
                format!("Allowed complex types with the {RECURSION_LIMIT} maximum depth")
            });
        }

        if rlp.is_list() {
            let mut items = Vec::new();
            let new_depth = depth + 1;
            
            let item_count = rlp.item_count().map_err(|e| {
                SigningError::from(SigningErrorType::Error_invalid_params)
                    .context(format!("Failed to get RLP item count: {}", e))
            })?;
            
            for i in 0..item_count {
                let item_rlp = rlp.at(i).map_err(|e| {
                    SigningError::from(SigningErrorType::Error_invalid_params)
                        .context(format!("Failed to get RLP item at index {}: {}", i, e))
                })?;
                let decoded_item = Self::decode_rlp_to_json(new_depth, &item_rlp)?;
                items.push(decoded_item);
            }

            Ok(Value::Array(items))
        } else {
            // Try to decode as different types
            let data = rlp.data().map_err(|e| {
                SigningError::from(SigningErrorType::Error_invalid_params)
                    .context(format!("Failed to get RLP data: {}", e))
            })?;

            // If it's empty data, return null
            if data.is_empty() {
                return Ok(Value::Null);
            }

            // Try to decode as address (20 bytes) first
            if data.len() == 20 {
                // Format as hex address string
                let address_hex = format!("0x{}", hex::encode(data, false));
                return Ok(json!({
                    "type": "address",
                    "value": address_hex
                }));
            }

            // For single byte values, check if it's likely a number or string
            if data.len() == 1 {
                let byte_val = data[0];
                // If it's a control character or high value, treat as number
                if byte_val < 32 || byte_val > 126 {
                    return Ok(json!({
                        "type": "number",
                        "value": byte_val as u64
                    }));
                }
                // Otherwise check if it's a letter (clearly a string)
                else if byte_val.is_ascii_alphabetic() {
                    return Ok(json!({
                        "type": "string",
                        "value": std::str::from_utf8(data).unwrap()
                    }));
                }
                // For digits and punctuation, we'll fall through to number parsing
            }

            // For multi-byte data, try UTF-8 string if it contains letters
            if data.len() > 1 {
                if let Ok(string) = std::str::from_utf8(data) {
                    // If it contains letters, treat as string
                    if string.chars().any(|c| c.is_ascii_alphabetic()) {
                        return Ok(json!({
                            "type": "string",
                            "value": string
                        }));
                    }
                }
            }

            // Try to decode as U256 number for single bytes or non-text data
            if let Ok(number) = U256::from_big_endian_slice(data) {
                // Check if it fits in u64 by comparing with U256::from(u64::MAX)
                if number <= U256::from(u64::MAX) {
                    // Convert to u64 by getting the low bytes
                    let bytes = number.to_big_endian_compact();
                    let mut u64_bytes = [0u8; 8];
                    if bytes.len() <= 8 {
                        let offset = 8 - bytes.len();
                        u64_bytes[offset..].copy_from_slice(&bytes);
                        let value = u64::from_be_bytes(u64_bytes);
                        return Ok(json!({
                            "type": "number", 
                            "value": value
                        }));
                    }
                }
                
                return Ok(json!({
                    "type": "bigint",
                    "value": format!("0x{}", hex::encode(number.to_big_endian_compact(), false))
                }));
            }

            // Default to hex-encoded data
            Ok(json!({
                "type": "data",
                "value": format!("0x{}", hex::encode(data, false))
            }))
        }
    }

    fn decode_transaction(tx_type: u8, rlp: &rlp::Rlp) -> SigningResult<Value> {
        if !rlp.is_list() {
            return SigningError::err(SigningErrorType::Error_invalid_params)
                .context("Transaction must be an RLP list");
        }

        let item_count = rlp.item_count().map_err(|e| {
            SigningError::from(SigningErrorType::Error_invalid_params)
                .context(format!("Failed to get transaction item count: {}", e))
        })?;

        match tx_type {
            0 => Self::decode_legacy_transaction(rlp, item_count),      // Legacy
            1 => Self::decode_eip2930_transaction(rlp, item_count),     // EIP-2930
            2 => Self::decode_eip1559_transaction(rlp, item_count),     // EIP-1559
            3 => Self::decode_eip4844_transaction(rlp, item_count),     // EIP-4844
            4 => Self::decode_eip7702_transaction(rlp, item_count),     // EIP-7702
            _ => {
                // Unknown transaction type, decode as generic array
                let initial_depth = 0;
                let mut tx_obj = serde_json::Map::new();
                tx_obj.insert("type".to_string(), json!(tx_type));
                tx_obj.insert("data".to_string(), Self::decode_rlp_to_json(initial_depth, rlp)?);
                Ok(Value::Object(tx_obj))
            }
        }
    }

    fn decode_legacy_transaction(rlp: &rlp::Rlp, item_count: usize) -> SigningResult<Value> {
        if item_count < 9 {
            return SigningError::err(SigningErrorType::Error_invalid_params)
                .context("Legacy transaction must have at least 9 fields");
        }

        let mut tx = serde_json::Map::new();
        tx.insert("type".to_string(), json!(0));
        tx.insert("chainId".to_string(), Self::decode_field_as_simple_value(rlp, 0)?);
        tx.insert("nonce".to_string(), Self::decode_field_as_simple_value(rlp, 1)?);
        tx.insert("gasPrice".to_string(), Self::decode_field_as_simple_value(rlp, 2)?);
        tx.insert("gasLimit".to_string(), Self::decode_field_as_simple_value(rlp, 3)?);
        tx.insert("to".to_string(), Self::decode_field_as_simple_value(rlp, 4)?);
        tx.insert("value".to_string(), Self::decode_field_as_simple_value(rlp, 5)?);
        tx.insert("data".to_string(), Self::decode_field_as_simple_value(rlp, 6)?);
        
        // For legacy transactions, v/r/s are the last 3 fields
        if item_count >= 9 {
            tx.insert("v".to_string(), Self::decode_field_as_simple_value(rlp, item_count - 3)?);
            tx.insert("r".to_string(), Self::decode_field_as_simple_value(rlp, item_count - 2)?);
            tx.insert("s".to_string(), Self::decode_field_as_simple_value(rlp, item_count - 1)?);
        }

        Ok(Value::Object(tx))
    }

    fn decode_eip2930_transaction(rlp: &rlp::Rlp, item_count: usize) -> SigningResult<Value> {
        if item_count < 8 {
            return SigningError::err(SigningErrorType::Error_invalid_params)
                .context("EIP-2930 transaction must have at least 8 fields");
        }

        let mut tx = serde_json::Map::new();
        tx.insert("type".to_string(), json!(1));
        tx.insert("chainId".to_string(), Self::decode_field_as_simple_value(rlp, 0)?);
        tx.insert("nonce".to_string(), Self::decode_field_as_simple_value(rlp, 1)?);
        tx.insert("gasPrice".to_string(), Self::decode_field_as_simple_value(rlp, 2)?);
        tx.insert("gasLimit".to_string(), Self::decode_field_as_simple_value(rlp, 3)?);
        tx.insert("to".to_string(), Self::decode_field_as_simple_value(rlp, 4)?);
        tx.insert("value".to_string(), Self::decode_field_as_simple_value(rlp, 5)?);
        tx.insert("data".to_string(), Self::decode_field_as_simple_value(rlp, 6)?);
        tx.insert("accessList".to_string(), Self::decode_field_as_simple_value(rlp, 7)?);
        
        // Unsigned EIP-2930 Transaction (8 fields)
        if item_count == 8 {
            return Ok(Value::Object(tx));
        }
        
        // Signed EIP-2930 Transaction (11 fields)
        if item_count >= 11 {
            tx.insert("yParity".to_string(), Self::decode_field_as_simple_value(rlp, 8)?);
            tx.insert("r".to_string(), Self::decode_field_as_simple_value(rlp, 9)?);
            tx.insert("s".to_string(), Self::decode_field_as_simple_value(rlp, 10)?);
        }

        Ok(Value::Object(tx))
    }

    fn decode_eip1559_transaction(rlp: &rlp::Rlp, item_count: usize) -> SigningResult<Value> {
        if item_count < 9 {
            return SigningError::err(SigningErrorType::Error_invalid_params)
                .context("EIP-1559 transaction must have at least 9 fields");
        }

        let mut tx = serde_json::Map::new();
        tx.insert("type".to_string(), json!(2));
        tx.insert("chainId".to_string(), Self::decode_field_as_simple_value(rlp, 0)?);
        tx.insert("nonce".to_string(), Self::decode_field_as_simple_value(rlp, 1)?);
        tx.insert("maxPriorityFeePerGas".to_string(), Self::decode_field_as_simple_value(rlp, 2)?);
        tx.insert("maxFeePerGas".to_string(), Self::decode_field_as_simple_value(rlp, 3)?);
        tx.insert("gasPrice".to_string(), Value::Null);
        tx.insert("gasLimit".to_string(), Self::decode_field_as_simple_value(rlp, 4)?);
        tx.insert("to".to_string(), Self::decode_field_as_simple_value(rlp, 5)?);
        tx.insert("value".to_string(), Self::decode_field_as_simple_value(rlp, 6)?);
        tx.insert("data".to_string(), Self::decode_field_as_simple_value(rlp, 7)?);
        tx.insert("accessList".to_string(), Self::decode_field_as_simple_value(rlp, 8)?);
        
        // Unsigned EIP-1559 Transaction (9 fields)
        if item_count == 9 {
            return Ok(Value::Object(tx));
        }
        
        // Signed EIP-1559 Transaction (12 fields)
        if item_count >= 12 {
            tx.insert("yParity".to_string(), Self::decode_field_as_simple_value(rlp, 9)?);
            tx.insert("r".to_string(), Self::decode_field_as_simple_value(rlp, 10)?);
            tx.insert("s".to_string(), Self::decode_field_as_simple_value(rlp, 11)?);
        }

        Ok(Value::Object(tx))
    }

    fn decode_eip4844_transaction(rlp: &rlp::Rlp, item_count: usize) -> SigningResult<Value> {
        if item_count < 11 {
            return SigningError::err(SigningErrorType::Error_invalid_params)
                .context("EIP-4844 transaction must have at least 11 fields");
        }

        let mut tx = serde_json::Map::new();
        tx.insert("type".to_string(), json!(3));
        tx.insert("chainId".to_string(), Self::decode_field_as_simple_value(rlp, 0)?);
        tx.insert("nonce".to_string(), Self::decode_field_as_simple_value(rlp, 1)?);
        tx.insert("maxPriorityFeePerGas".to_string(), Self::decode_field_as_simple_value(rlp, 2)?);
        tx.insert("maxFeePerGas".to_string(), Self::decode_field_as_simple_value(rlp, 3)?);
        tx.insert("gasPrice".to_string(), Value::Null);
        tx.insert("gasLimit".to_string(), Self::decode_field_as_simple_value(rlp, 4)?);
        tx.insert("to".to_string(), Self::decode_field_as_simple_value(rlp, 5)?);
        tx.insert("value".to_string(), Self::decode_field_as_simple_value(rlp, 6)?);
        tx.insert("data".to_string(), Self::decode_field_as_simple_value(rlp, 7)?);
        tx.insert("accessList".to_string(), Self::decode_field_as_simple_value(rlp, 8)?);
        tx.insert("maxFeePerBlobGas".to_string(), Self::decode_field_as_simple_value(rlp, 9)?);
        tx.insert("blobVersionedHashes".to_string(), Self::decode_field_as_simple_value(rlp, 10)?);
        
        // Unsigned EIP-4844 Transaction (11 fields)
        if item_count == 11 {
            return Ok(Value::Object(tx));
        }
        
        // Signed EIP-4844 Transaction (14 fields)
        if item_count >= 14 {
            tx.insert("yParity".to_string(), Self::decode_field_as_simple_value(rlp, 11)?);
            tx.insert("r".to_string(), Self::decode_field_as_simple_value(rlp, 12)?);
            tx.insert("s".to_string(), Self::decode_field_as_simple_value(rlp, 13)?);
        }

        Ok(Value::Object(tx))
    }

    fn decode_eip7702_transaction(rlp: &rlp::Rlp, item_count: usize) -> SigningResult<Value> {
        if item_count < 10 {
            return SigningError::err(SigningErrorType::Error_invalid_params)
                .context("EIP-7702 transaction must have at least 10 fields");
        }

        let mut tx = serde_json::Map::new();
        tx.insert("type".to_string(), json!(4));
        tx.insert("chainId".to_string(), Self::decode_field_as_simple_value(rlp, 0)?);
        tx.insert("nonce".to_string(), Self::decode_field_as_simple_value(rlp, 1)?);
        tx.insert("maxPriorityFeePerGas".to_string(), Self::decode_field_as_simple_value(rlp, 2)?);
        tx.insert("maxFeePerGas".to_string(), Self::decode_field_as_simple_value(rlp, 3)?);
        tx.insert("gasPrice".to_string(), Value::Null);
        tx.insert("gasLimit".to_string(), Self::decode_field_as_simple_value(rlp, 4)?);
        tx.insert("to".to_string(), Self::decode_field_as_simple_value(rlp, 5)?);
        tx.insert("value".to_string(), Self::decode_field_as_simple_value(rlp, 6)?);
        tx.insert("data".to_string(), Self::decode_field_as_simple_value(rlp, 7)?);
        tx.insert("accessList".to_string(), Self::decode_field_as_simple_value(rlp, 8)?);
        tx.insert("authorizationList".to_string(), Self::decode_authorization_list_simple(rlp, 9)?);
        
        // Unsigned EIP-7702 Transaction (10 fields)
        if item_count == 10 {
            return Ok(Value::Object(tx));
        }
        
        // Signed EIP-7702 Transaction (13 fields)
        if item_count >= 13 {
            tx.insert("yParity".to_string(), Self::decode_field_as_simple_value(rlp, 10)?);
            tx.insert("r".to_string(), Self::decode_field_as_simple_value(rlp, 11)?);
            tx.insert("s".to_string(), Self::decode_field_as_simple_value(rlp, 12)?);
        }

        Ok(Value::Object(tx))
    }



    fn decode_field_as_simple_value(rlp: &rlp::Rlp, index: usize) -> SigningResult<Value> {
        let field_rlp = rlp.at(index).map_err(|e| {
            SigningError::from(SigningErrorType::Error_invalid_params)
                .context(format!("Failed to get field at index {}: {}", index, e))
        })?;
        
        Self::decode_rlp_to_simple_value(&field_rlp)
    }

    fn decode_rlp_to_simple_value(rlp: &rlp::Rlp) -> SigningResult<Value> {
        if rlp.is_list() {
            let mut items = Vec::new();
            let item_count = rlp.item_count().map_err(|e| {
                SigningError::from(SigningErrorType::Error_invalid_params)
                    .context(format!("Failed to get RLP item count: {}", e))
            })?;
            
            for i in 0..item_count {
                let item_rlp = rlp.at(i).map_err(|e| {
                    SigningError::from(SigningErrorType::Error_invalid_params)
                        .context(format!("Failed to get RLP item at index {}: {}", i, e))
                })?;
                let decoded_item = Self::decode_rlp_to_simple_value(&item_rlp)?;
                items.push(decoded_item);
            }

            Ok(Value::Array(items))
        } else {
            // Try to decode as different types
            let data = rlp.data().map_err(|e| {
                SigningError::from(SigningErrorType::Error_invalid_params)
                    .context(format!("Failed to get RLP data: {}", e))
            })?;

            // If it's empty data, return 0 for numeric fields (like yParity)
            if data.is_empty() {
                return Ok(json!(0));
            }

            // Try to decode as address (20 bytes) first
            if data.len() == 20 {
                // Format as hex address string
                let address_hex = format!("0x{}", hex::encode(data, false));
                return Ok(Value::String(address_hex));
            }

            // For transaction fields, we should prioritize numeric interpretation
            // Only treat as string if it's clearly textual data (contains multiple letters and is valid UTF-8)
            if data.len() > 3 {
                if let Ok(string) = std::str::from_utf8(data) {
                    // Only treat as string if it has multiple letters and looks like text
                    let letter_count = string.chars().filter(|c| c.is_ascii_alphabetic()).count();
                    let total_chars = string.chars().count();
                    // If more than half the characters are letters, treat as string
                    if letter_count > 1 && letter_count * 2 > total_chars {
                        return Ok(Value::String(string.to_string()));
                    }
                }
            }

            // Try to decode as U256 number for single bytes or non-text data
            if let Ok(number) = U256::from_big_endian_slice(data) {
                // Check if it fits in u64 by comparing with U256::from(u64::MAX)
                if number <= U256::from(u64::MAX) {
                    // Convert to u64 by getting the low bytes
                    let bytes = number.to_big_endian_compact();
                    let mut u64_bytes = [0u8; 8];
                    if bytes.len() <= 8 {
                        let offset = 8 - bytes.len();
                        u64_bytes[offset..].copy_from_slice(&bytes);
                        let value = u64::from_be_bytes(u64_bytes);
                        return Ok(json!(value));
                    }
                }
                
                return Ok(Value::String(format!("0x{}", hex::encode(number.to_big_endian_compact(), false))));
            }

            // Default to hex-encoded data
            Ok(Value::String(format!("0x{}", hex::encode(data, false))))
        }
    }



    fn decode_authorization_list_simple(rlp: &rlp::Rlp, index: usize) -> SigningResult<Value> {
        let field_rlp = rlp.at(index).map_err(|e| {
            SigningError::from(SigningErrorType::Error_invalid_params)
                .context(format!("Failed to get authorizationList at index {}: {}", index, e))
        })?;

        if !field_rlp.is_list() {
            return Ok(Value::Array(vec![])); // Empty authorization list
        }

        let mut authorizations = Vec::new();
        let auth_count = field_rlp.item_count().map_err(|e| {
            SigningError::from(SigningErrorType::Error_invalid_params)
                .context(format!("Failed to get authorization count: {}", e))
        })?;

        for i in 0..auth_count {
            let auth_rlp = field_rlp.at(i).map_err(|e| {
                SigningError::from(SigningErrorType::Error_invalid_params)
                    .context(format!("Failed to get authorization at index {}: {}", i, e))
            })?;

            if !auth_rlp.is_list() {
                continue; // Skip invalid authorization
            }

            let auth_item_count = auth_rlp.item_count().map_err(|e| {
                SigningError::from(SigningErrorType::Error_invalid_params)
                    .context(format!("Failed to get authorization item count: {}", e))
            })?;

            if auth_item_count != 6 {
                continue; // Skip invalid authorization (should have 6 fields)
            }

            // Decode authorization fields: [chainId, address, nonce, yParity, r, s]
            let mut auth_obj = serde_json::Map::new();
            
            // chainId (field 0)
            auth_obj.insert("chainId".to_string(), Self::decode_rlp_to_simple_value(&auth_rlp.at(0).unwrap())?);

            // address (field 1)
            auth_obj.insert("address".to_string(), Self::decode_rlp_to_simple_value(&auth_rlp.at(1).unwrap())?);

            // nonce (field 2)
            auth_obj.insert("nonce".to_string(), Self::decode_rlp_to_simple_value(&auth_rlp.at(2).unwrap())?);

            // signature object with yParity, r, s
            let mut signature_obj = serde_json::Map::new();
            signature_obj.insert("yParity".to_string(), Self::decode_rlp_to_simple_value(&auth_rlp.at(3).unwrap())?);
            signature_obj.insert("r".to_string(), Self::decode_rlp_to_simple_value(&auth_rlp.at(4).unwrap())?);
            signature_obj.insert("s".to_string(), Self::decode_rlp_to_simple_value(&auth_rlp.at(5).unwrap())?);

            auth_obj.insert("signature".to_string(), Value::Object(signature_obj));

            authorizations.push(Value::Object(auth_obj));
        }

        Ok(Value::Array(authorizations))
    }
}
