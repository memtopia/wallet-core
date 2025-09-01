// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#![allow(clippy::missing_safety_doc)]

use tw_macros::tw_ffi;
use tw_memory::ffi::tw_string::TWString;
use tw_memory::ffi::{Nonnull, NullableMut, RawPtrTrait};
use tw_misc::try_or_else;
use crate::ffi::utils::tma_utils::{generate_export_key_pkcs8, user_export_data, UserExportCompleteResponse};

/// Generates a new export key pair in PKCS#8 format.
/// 
/// \return JSON string containing the generated key pair with public_key and private_key fields.
///         Returns null if generation fails.
#[tw_ffi(ty = static_function, class = TWTMAUtils, name = GenerateExportKeyPkcs8)]
#[no_mangle]
pub unsafe extern "C" fn tw_tma_utils_generate_export_key_pkcs8() -> NullableMut<TWString> {
    let result = try_or_else!(generate_export_key_pkcs8(), std::ptr::null_mut);
    let json_string = try_or_else!(serde_json::to_string(&result), std::ptr::null_mut);
    TWString::from(json_string).into_ptr()
}

/// Decrypts user export data using the provided private key and response.
/// 
/// \param private_key_base64 Base64 encoded private key in PKCS#8 format.
/// \param encrypted_key_material Base64 encoded encrypted key material.
/// \param ephemeral_public_key Base64 encoded ephemeral public key.
/// \param user_id User ID string.
/// \return JSON string containing the decrypted key material with key_type, material_type, and mnemonic fields.
///         Returns empty JSON object if decryption fails.
#[tw_ffi(ty = static_function, class = TWTMAUtils, name = UserExportData)]
#[no_mangle]
pub unsafe extern "C" fn tw_tma_utils_user_export_data(
    private_key_base64: Nonnull<TWString>,
    encrypted_key_material: Nonnull<TWString>,
    ephemeral_public_key: Nonnull<TWString>,
    user_id: Nonnull<TWString>,
) -> NullableMut<TWString> {
    let private_key_base64 = try_or_else!(TWString::from_ptr_as_ref(private_key_base64), std::ptr::null_mut);
    let private_key_str = try_or_else!(private_key_base64.as_str(), std::ptr::null_mut);
    
    let encrypted_key_material = try_or_else!(TWString::from_ptr_as_ref(encrypted_key_material), std::ptr::null_mut);
    let encrypted_key_material_str = try_or_else!(encrypted_key_material.as_str(), std::ptr::null_mut);
    
    let ephemeral_public_key = try_or_else!(TWString::from_ptr_as_ref(ephemeral_public_key), std::ptr::null_mut);
    let ephemeral_public_key_str = try_or_else!(ephemeral_public_key.as_str(), std::ptr::null_mut);
    
    let user_id = try_or_else!(TWString::from_ptr_as_ref(user_id), std::ptr::null_mut);
    let user_id_str = try_or_else!(user_id.as_str(), std::ptr::null_mut);

    let response = UserExportCompleteResponse {
        encrypted_key_material: encrypted_key_material_str.to_string(),
        ephemeral_public_key: ephemeral_public_key_str.to_string(),
        user_id: user_id_str.to_string(),
    };

    // 处理 user_export_data 可能的错误
    let json_string = match user_export_data(private_key_str, &response) {
        Ok(result) => {
            serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
        }
        Err(_) => {
            "{}".to_string()
        }
    };
    
    TWString::from(json_string).into_ptr()
}