// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

use std::borrow::Cow;
use tw_evm::evm_context::StandardEvmContext;
use tw_evm::modules::rlp_decoder::RlpDecoder;
use tw_encoding::hex;
use tw_proto::EthereumRlp::Proto;

#[test]
fn test_rlp_decode_simple_number() {
    // RLP encoded number 42 (0x2a)
    let encoded = hex::decode("2a").unwrap();
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    

    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    assert_eq!(json["type"], "number");
    assert_eq!(json["value"], 42);
}

#[test]
fn test_rlp_decode_empty() {
    // RLP encoded empty string
    let encoded = hex::decode("80").unwrap();
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    

    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    assert!(json.is_null());
}

#[test]
fn test_rlp_decode_string() {
    // RLP encoded string "hello"
    let encoded = hex::decode("8568656c6c6f").unwrap();
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    

    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    assert_eq!(json["type"], "string");
    assert_eq!(json["value"], "hello");
}

#[test]
fn test_rlp_decode_list() {
    // RLP encoded list ["hello", 42]
    // List header: 0xc7 (list of 7 bytes)
    // "hello": 0x8568656c6c6f (6 bytes)
    // 42: 0x2a (1 byte)
    let encoded = hex::decode("c78568656c6c6f2a").unwrap();
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    

    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    assert!(json.is_array());
    
    let array = json.as_array().unwrap();
    assert_eq!(array.len(), 2);
    
    assert_eq!(array[0]["type"], "string");
    assert_eq!(array[0]["value"], "hello");
    
    assert_eq!(array[1]["type"], "number");
    assert_eq!(array[1]["value"], 42);
}

#[test]
fn test_rlp_decode_address() {
    // RLP encoded Ethereum address (20 bytes)
    let address_bytes = hex::decode("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
    let mut encoded = vec![0x94]; // RLP header for 20 bytes
    encoded.extend_from_slice(&address_bytes);
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    

    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    assert_eq!(json["type"], "address");
    assert_eq!(json["value"], "0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
}

#[test]
fn test_rlp_decode_large_number() {
    // RLP encoded large number that doesn't fit in u64
    let large_num_bytes = hex::decode("0100000000000000000000000000000000").unwrap(); // 2^128
    let mut encoded = vec![0x90]; // RLP header for 16 bytes
    encoded.extend_from_slice(&large_num_bytes);
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    

    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    assert_eq!(json["type"], "bigint");
    assert!(json["value"].as_str().unwrap().starts_with("0x"));
}

#[test]
fn test_rlp_decode_transaction() {
    // RLP encoded large number that doesn't fit in u64
    let large_num_bytes = hex::decode("02f87083aa36a7588459682f00845f5e1000830465d8947d0539bc9896d24bed03473c5a2a991771e18edc80b844a9059cbb000000000000000000000000c4811bfd16098b1a50fe20e87f0224de531832fb0000000000000000000000000000000000000000000000000000000000003018c0").unwrap(); // 2^128
    let mut encoded = vec![]; // RLP header for 16 bytes
    encoded.extend_from_slice(&large_num_bytes);

    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };

    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);



    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    println!("json = {:?}", json.to_string())
}

#[test]
fn test_rlp_decode_eip1559_transaction() {
    // EIP-1559 transaction from the user's example
    let raw_tx = "02f8b383aa36a7588459682f00845f5e1000830465d8947d0539bc9896d24bed03473c5a2a991771e18edc80b844a9059cbb000000000000000000000000c4811bfd16098b1a50fe20e87f0224de531832fb0000000000000000000000000000000000000000000000000000000000003018c080a0341211c58760818ab9e0a1c2ac8fec466ecb1b48937e6c78bc0a4a04a9e93376a0690015d5381c880d20fdeced06f84a8fd3763c100519d59cd15f2e941189853e";
    
    let encoded = hex::decode(raw_tx).unwrap();
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    
    // Check expected values
    assert_eq!(json["type"], 2);
    assert_eq!(json["chainId"], 11155111);  // 0xaa36a7
    assert_eq!(json["nonce"], 88);          // 0x58
    assert_eq!(json["gasLimit"], 288216);   // 0x0465d8
    assert_eq!(json["maxPriorityFeePerGas"], 1500000000);
    assert_eq!(json["maxFeePerGas"], 1600000000);
    assert_eq!(json["value"], 0);
    assert_eq!(json["yParity"], 0);
    
    // Should not contain garbled text
    assert!(!output.json.contains("Yh/"));
    assert!(!output.json.contains("\\u0000"));
    assert!(!output.json.contains("\"X\""));
}

#[test]
fn test_rlp_decode_unsigned_eip1559_transaction() {
    // Unsigned EIP-1559 transaction (9 fields, no signature)
    // This would be a transaction before signing
    let raw_tx = "02e583aa36a7588459682f00845f5e1000830465d8947d0539bc9896d24bed03473c5a2a991771e18edc80b844a9059cbb000000000000000000000000c4811bfd16098b1a50fe20e87f0224de531832fb0000000000000000000000000000000000000000000000000000000000003018c0";
    
    let encoded = hex::decode(raw_tx).unwrap();
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    
    // Check expected values for unsigned transaction
    assert_eq!(json["type"], 2);
    assert_eq!(json["chainId"], 11155111);
    assert_eq!(json["nonce"], 88);
    assert_eq!(json["gasLimit"], 288216);
    
    // Unsigned transaction should not have signature fields
    assert!(json.get("yParity").is_none() || json["yParity"].is_null());
    assert!(json.get("r").is_none() || json["r"].is_null());
    assert!(json.get("s").is_none() || json["s"].is_null());
}

#[test]
fn test_rlp_decode_eip7702_field_count_handling() {
    // Test that the existing EIP-7702 transaction (13 fields, signed) works correctly
    // and verify that our field count logic is working
    let raw_tx = "04f8c1010201028310000094b009164b84aa0073c81614c53f49010c5f2757038080c0f85cf85a019400000000000000000000000000000000000000000301a0dbad281c03f8681006bfa1778e9ec6c81a1e0cde8c0e280c0306592cede52c64a02d54d1a175ef89edcac9aacdc9725c4f145abb354654771ea097da7e7945725e01a06894caa8b2e6846cf5a099b9d2a16b1123c634e4aed4a4de527c67e81bab9c2aa00497adcc2a8071c12f5f89df8e07b8f3b1ae5d18448d49eda6b2e10dcd9888a6";
    
    let encoded = hex::decode(raw_tx).unwrap();
    
    let input = Proto::DecodingInput {
        encoded: Cow::from(encoded),
    };
    
    let output = RlpDecoder::<StandardEvmContext>::decode_with_proto(input);
    
    let json: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    
    // Check that this is recognized as EIP-7702 (type 4)
    assert_eq!(json["type"], 4);
    
    // Should have authorizationList
    assert!(json.get("authorizationList").is_some());
    
    // Signed transaction should have signature fields
    assert!(json.get("yParity").is_some());
    assert!(json.get("r").is_some());
    assert!(json.get("s").is_some());
    
    // Verify the authorizationList structure
    let auth_list = &json["authorizationList"];
    assert!(auth_list.is_array());
    if auth_list.as_array().unwrap().len() > 0 {
        let first_auth = &auth_list[0];
        assert!(first_auth.get("chainId").is_some());
        assert!(first_auth.get("address").is_some());
        assert!(first_auth.get("nonce").is_some());
        assert!(first_auth.get("signature").is_some());
    }
}
