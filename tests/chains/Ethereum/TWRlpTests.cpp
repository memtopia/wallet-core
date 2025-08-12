// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#include "TrustWalletCore/TWEthereumRlp.h"
#include "proto/EthereumRlp.pb.h"
#include "HexCoding.h"
#include "TestUtilities.h"
#include "uint256.h"

#include <gtest/gtest.h>

using namespace TW;

TEST(TWEthereumRlp, Eip1559) {
    auto chainId = store(10);
    auto nonce = store(6);
    auto maxInclusionFeePerGas = 2'000'000'000;
    auto maxFeePerGas = store(3'000'000'000);
    auto gasLimit = store(21'100);
    const auto* to = "0x6b175474e89094c44da98b954eedeac495271d0f";
    auto amount = 0;
    auto payload = parse_hex("a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000000001ee0c29f50cb1");

    EthereumRlp::Proto::EncodingInput input;
    auto* list = input.mutable_item()->mutable_list();

    list->add_items()->set_number_u256(chainId.data(), chainId.size());
    list->add_items()->set_number_u256(nonce.data(), nonce.size());
    list->add_items()->set_number_u64(maxInclusionFeePerGas);
    list->add_items()->set_number_u256(maxFeePerGas.data(), maxFeePerGas.size());
    list->add_items()->set_number_u256(gasLimit.data(), gasLimit.size());
    list->add_items()->set_address(to);
    list->add_items()->set_number_u64(amount);
    list->add_items()->set_data(payload.data(), payload.size());
    // Append an empty `access_list`.
    list->add_items()->mutable_list();

    auto inputData = input.SerializeAsString();
    auto inputTWData = WRAPD(TWDataCreateWithBytes((const uint8_t *)inputData.data(), inputData.size()));
    auto outputTWData = WRAPD(TWEthereumRlpEncode(TWCoinTypeEthereum, inputTWData.get()));

    EthereumRlp::Proto::EncodingOutput output;
    output.ParseFromArray(TWDataBytes(outputTWData.get()), static_cast<int>(TWDataSize(outputTWData.get())));

    EXPECT_EQ(output.error(), Common::Proto::SigningError::OK);
    EXPECT_TRUE(output.error_message().empty());
    EXPECT_EQ(hex(output.encoded()), "f86c0a06847735940084b2d05e0082526c946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000000001ee0c29f50cb1c0");
}




TEST(TWEthereumRlp, DecodeEIP1559Transaction) {
    // Test decoding a real EIP-1559 transaction
    EthereumRlp::Proto::DecodingInput input;
    auto rlpData = parse_hex("02f8b383aa36a7588459682f00845f5e1000830465d8947d0539bc9896d24bed03473c5a2a991771e18edc80b844a9059cbb000000000000000000000000c4811bfd16098b1a50fe20e87f0224de531832fb0000000000000000000000000000000000000000000000000000000000003018c080a0341211c58760818ab9e0a1c2ac8fec466ecb1b48937e6c78bc0a4a04a9e93376a0690015d5381c880d20fdeced06f84a8fd3763c100519d59cd15f2e941189853e");

    auto inputTWData = WRAPD(TWDataCreateWithBytes(rlpData.data(), rlpData.size()));
    auto resultTWString = WRAPS(TWEthereumRlpDecode(TWCoinTypeEthereum, inputTWData.get()));

    auto jsonResult = std::string(TWStringUTF8Bytes(resultTWString.get()));
    std::cout << "DecodeEIP1559Transaction result: " << jsonResult << std::endl;
    
    EXPECT_FALSE(jsonResult.empty());
    
    // Check if it's an error message - if so, print it for debugging
    if (jsonResult.find("error") != std::string::npos) {
        std::cout << "ERROR found in result: " << jsonResult << std::endl;
        // For debugging purposes, we still want to see the error, but test should fail
        FAIL() << "RLP decode returned error: " << jsonResult;
        return;
    }
    
    // Check that it contains expected transaction fields
    EXPECT_NE(jsonResult.find("\"chainId\":11155111"), std::string::npos);
    EXPECT_NE(jsonResult.find("\"nonce\":88"), std::string::npos);
    EXPECT_NE(jsonResult.find("\"type\":2"), std::string::npos);
    EXPECT_NE(jsonResult.find("\"gasLimit\":288216"), std::string::npos);
    EXPECT_NE(jsonResult.find("\"maxFeePerGas\":1600000000"), std::string::npos);
    EXPECT_NE(jsonResult.find("\"maxPriorityFeePerGas\":1500000000"), std::string::npos);
    EXPECT_NE(jsonResult.find("\"to\":\"0x7d0539bc9896d24bed03473c5a2a991771e18edc\""), std::string::npos);
    EXPECT_NE(jsonResult.find("\"value\":0"), std::string::npos);
    EXPECT_NE(jsonResult.find("\"yParity\":0"), std::string::npos);
}
