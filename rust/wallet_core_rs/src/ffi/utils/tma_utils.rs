use base64::Engine;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, Serializable};
use p256::SecretKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::prelude::StdRng;
use rand::SeedableRng;
pub type HpkeKem = DhP256HkdfSha256;
type HpkeAead = AesGcm256;
type HpkeKdf = HkdfSha256;
#[derive(Debug, Clone)]
pub struct ImportKeyOptions {
    pub name: String,
    pub named_curve: String,
    pub extractable: bool,
    pub key_usages: Vec<String>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportedKeyPairPkcs8 {
    pub public_key: String,
    pub private_key: String,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserExportKeyResult {
    pub key_type: String,
    pub material_type: String,
    pub mnemonic: String,
}
#[derive(Debug, Clone)]
pub struct UserExportCompleteResponse {
    pub encrypted_key_material: String,
    pub ephemeral_public_key: String,
    pub user_id: String,
}
pub fn export_private_key_pkcs8(
    private_key: &<HpkeKem as KemTrait>::PrivateKey,
) -> Result<String, String> {
    let private_key_bytes = private_key.to_bytes();
    let secret_key = SecretKey::from_bytes(&private_key_bytes)
        .map_err(|e| format!("Failed to create p256 SecretKey: {}", e))?;
    let pkcs8_der = secret_key
        .to_pkcs8_der()
        .map_err(|e| format!("Failed to export private key to PKCS#8: {}", e))?;
    let base64_encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8_der.as_bytes());
    Ok(base64_encoded)
}
pub fn user_export_decrypt(
    recipient_key: &<HpkeKem as KemTrait>::PrivateKey,
    response: &UserExportCompleteResponse,
) -> Result<UserExportKeyResult, String> {
    let ephemeral_public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.ephemeral_public_key)
        .map_err(|e| format!("Failed to decode ephemeral public key from base64: {}", e))?;
    let encrypted_key_material_bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.encrypted_key_material)
        .map_err(|e| format!("Failed to decode encrypted key material from base64: {}", e))?;
    let info_str = format!("cubist-signer::UserExportOwner::{}", response.user_id);
    let info = info_str.as_bytes();
    let ephemeral_public_key =
        <HpkeKem as KemTrait>::EncappedKey::from_bytes(&ephemeral_public_key_bytes)
            .map_err(|e| format!("Failed to deserialize ephemeral public key: {}", e))?;
    if encrypted_key_material_bytes.len() < 16 {
        return Err("Encrypted key material too short".to_string());
    }
    let tag_size = 16; // AES-GCM tag size
    let ciphertext_len = encrypted_key_material_bytes.len() - tag_size;
    let ciphertext = &encrypted_key_material_bytes[..ciphertext_len];
    let tag_bytes = &encrypted_key_material_bytes[ciphertext_len..];
    let mut receiver_ctx = hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeR::Base,
        recipient_key,
        &ephemeral_public_key,
        info,
    )
    .map_err(|e| format!("Failed to set up HPKE receiver: {}", e))?;
    let mut ciphertext_copy = ciphertext.to_vec();
    let tag = hpke::aead::AeadTag::<HpkeAead>::from_bytes(tag_bytes)
        .map_err(|e| format!("Failed to deserialize AEAD tag: {}", e))?;
    receiver_ctx
        .open_in_place_detached(&mut ciphertext_copy, &[], &tag)
        .map_err(|e| format!("Failed to decrypt with HPKE: {}", e))?;
    let decrypted_key_material: UserExportKeyResult = serde_json::from_slice(&ciphertext_copy)
        .map_err(|e| format!("Failed to parse decrypted JSON: {}", e))?;
    Ok(decrypted_key_material)
}
pub fn import_private_key_pkcs8(
    key_data: &str,
    options: &ImportKeyOptions,
) -> Result<<HpkeKem as KemTrait>::PrivateKey, String> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_data)
        .map_err(|e| format!("Failed to decode key data from base64: {}", e))?;
    if options.name != "ECDH" && options.name != "ECDSA" {
        return Err(format!("Unsupported algorithm name: {}", options.name));
    }
    if !options
        .key_usages
        .iter()
        .any(|usage| usage == "deriveBits" || usage == "deriveKey")
    {
        return Err("Key usage must include 'deriveBits' or 'deriveKey'".to_string());
    }
    let secret_key = SecretKey::from_pkcs8_der(&key_bytes)
        .map_err(|e| format!("Failed to import private key from PKCS#8: {}", e))?;
    let private_key_bytes = secret_key.to_bytes();
    let private_key = <HpkeKem as KemTrait>::PrivateKey::from_bytes(&private_key_bytes)
        .map_err(|e| format!("Failed to import private key from bytes: {}", e))?;
    Ok(private_key)
}
/// need export
pub fn generate_export_key_pkcs8() -> Result<ExportedKeyPairPkcs8, String> {
    let mut csprng = StdRng::from_os_rng();
    let (private_key, public_key) = HpkeKem::gen_keypair(&mut csprng);
    let public_key_bytes = public_key.to_bytes();
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key_bytes);
    let private_key_pkcs8 = export_private_key_pkcs8(&private_key)?;
    Ok(ExportedKeyPairPkcs8 {
        public_key: public_key_b64,
        private_key: private_key_pkcs8,
    })
}
/// need export
pub fn user_export_data(
    private_key_base64: &str,
    response: &UserExportCompleteResponse,
) -> Result<UserExportKeyResult, String> {
    let recipient_private_key = import_private_key_pkcs8(
        private_key_base64,
        &ImportKeyOptions {
            name: "ECDH".to_string(),
            named_curve: "P-256".to_string(),
            extractable: true,
            key_usages: vec!["deriveBits".to_string()],
        },
    )?;
    let decrypted_key_material = user_export_decrypt(&recipient_private_key, &response)?;
    Ok(decrypted_key_material)
}
mod tests {
    use crate::ffi::utils::tma_utils::{user_export_data, UserExportCompleteResponse};

    #[test]
    fn test_add() {
        let private_key = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTdmCdzWYNxJcO+l68IJ3KPOouYk6f5yc+09XKKOsDA6hRANCAAQLnHlnv+GcbzfbRwFX1DzgsGE7gwGKDy4+TPW/pN9BRVWlqvJksAF6r5Ic8PnHMACkHWpHl8jvH3LMho1aDzV6";

        let encrypted_key_material = "NvExYSbBeb6NYahQ/+7YcWH3oG9NCxwW11SbEF7qQB3SyoO1Tk2/poSne/ltdip5tqhpPKq0F/E9cwLTU9PRDqt+sdD8pZ0CHNca9WnnSSPEckyEqbC/m5T8diJSMiI1pxmfpDh+mZakxjFDPBdF8MeWkVWXjMjKLi3Lv0IaRLxXsh1AIaaLWuSk3QJEkw48VMROmXagaAFzdtgXZxFqhkHdCEtOO0YoRQyegHF6eQ3+hmQoQQOIm3cMeenTyuSaybQFIEcsWlIWbwffI9NYy73xlWpzXXNQXOQpeiZQ4voQebZ82MI5OS40JWd4yCtyxYwBmr2v3H3+j4doiixcBQE7c2h1sYdGkvy4dqZRf+cUdyzTSx0qxw==";

        let pub_key  = "BMJP6fWB9jYPnE//q0ib1VDlChnpA9xymF5QxHSVat/BN052UaUIASD8LkWMRzDlcjjxB5EC3CO6CXz7h3hE9vM=";

        let user_id = "User#79bde81d-4abe-4053-9174-7ea1797fc8f2";
        let a = user_export_data(
            private_key,
            &UserExportCompleteResponse {
                encrypted_key_material: encrypted_key_material.to_string(),
                ephemeral_public_key: pub_key.to_string(),
                user_id: user_id.to_string(),
            },
        );

        println!("result = {:?}", a)
    }
}