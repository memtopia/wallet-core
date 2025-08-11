// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#pragma once

#include "TWBase.h"
#include "TWCoinType.h"
#include "TWData.h"
#include "TWString.h"

TW_EXTERN_C_BEGIN

TW_EXPORT_STRUCT
struct TWEthereumRlp;

/// Encode an item or a list of items as Eth RLP binary format.
///
/// \param coin EVM-compatible coin type.
/// \param input Non-null serialized `EthereumRlp::Proto::EncodingInput`.
/// \return serialized `EthereumRlp::Proto::EncodingOutput`.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWEthereumRlpEncode(enum TWCoinType coin, TWData* _Nonnull input);

/// Decode RLP encoded data to JSON format.
///
/// \param coin EVM-compatible coin type.
/// \param input Non-null serialized `EthereumRlp::Proto::DecodingInput`.
/// \return JSON string representation of the decoded RLP data.
TW_EXPORT_STATIC_METHOD
TWString* _Nonnull TWEthereumRlpDecode(enum TWCoinType coin, TWData* _Nonnull input);

TW_EXTERN_C_END
