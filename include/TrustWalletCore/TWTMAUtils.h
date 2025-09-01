// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#pragma once

#include "TWBase.h"
#include "TWString.h"

TW_EXTERN_C_BEGIN

TW_EXPORT_CLASS
struct TWTMAUtils;

/// Generates a new export key pair in PKCS#8 format.
/// 
/// \return JSON string containing the generated key pair with public_key and private_key fields.
/// Returns null if generation fails.
TW_EXPORT_STATIC_METHOD TWString *_Nullable TWTMAUtilsGenerateExportKeyPkcs8();

/// Decrypts user export data using the provided private key and response.
/// 
/// \param private_key_base64 Base64 encoded private key in PKCS#8 format.
/// \param encrypted_key_material Base64 encoded encrypted key material.
/// \param ephemeral_public_key Base64 encoded ephemeral public key.
/// \param user_id User ID string.
/// \return JSON string containing the decrypted key material with key_type, material_type, and mnemonic fields.
/// Returns empty JSON object if decryption fails.
TW_EXPORT_STATIC_METHOD TWString *_Nullable TWTMAUtilsUserExportData(TWString *_Nonnull privateKeyBase64, TWString *_Nonnull encryptedKeyMaterial, TWString *_Nonnull ephemeralPublicKey, TWString *_Nonnull userId);

TW_EXTERN_C_END
