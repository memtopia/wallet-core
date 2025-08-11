// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#include <TrustWalletCore/TWEthereumRlp.h>

#include "Data.h"
#include "proto/EthereumRlp.pb.h"
#include "rust/Wrapper.h"

using namespace TW;

TWData* _Nonnull TWEthereumRlpEncode(enum TWCoinType coin, TWData* _Nonnull input) {
    const Data& dataIn = *(reinterpret_cast<const Data*>(input));

    const Rust::TWDataWrapper dataInPtr(dataIn);
    Rust::TWDataWrapper dataOutPtr = Rust::tw_ethereum_rlp_encode(static_cast<uint32_t>(coin), dataInPtr.get());

    auto dataOut = dataOutPtr.toDataOrDefault();
    return TWDataCreateWithBytes(dataOut.data(), dataOut.size());
}

TWString* _Nonnull TWEthereumRlpDecode(enum TWCoinType coin, TWData* _Nonnull input) {
    const Data& dataIn = *(reinterpret_cast<const Data*>(input));

    const Rust::TWDataWrapper dataInPtr(dataIn);
    Rust::TWDataWrapper dataOutPtr = Rust::tw_ethereum_rlp_decode(static_cast<uint32_t>(coin), dataInPtr.get());

    auto dataOut = dataOutPtr.toDataOrDefault();

    // Rust should now always return valid proto data, even for errors
    // But handle the edge case where it might still return empty data
    if (dataOut.empty()) {
        return TWStringCreateWithUTF8Bytes("{\"error\": \"FFI returned empty data - this should not happen\"}");
    }

    // Convert the proto-serialized output to DecodingOutput and extract the JSON string
    auto output = TW::EthereumRlp::Proto::DecodingOutput();
    if (!output.ParseFromArray(dataOut.data(), static_cast<int>(dataOut.size()))) {
        return TWStringCreateWithUTF8Bytes("{\"error\": \"Failed to parse proto response from Rust FFI\"}");
    }

    // The JSON field should contain either valid JSON result or error JSON
    const std::string& jsonResult = output.json();
    if (jsonResult.empty()) {
        return TWStringCreateWithUTF8Bytes("{\"error\": \"Empty JSON result from Rust\"}");
    }

    return TWStringCreateWithUTF8Bytes(jsonResult.c_str());
}
