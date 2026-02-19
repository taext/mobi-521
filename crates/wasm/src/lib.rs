use mobi521_core::keys::{encode_public_key, encode_secret_key, KeyPair};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Call once on startup to get readable panic messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize)]
pub struct KeyPairResult {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "privateKey")]
    pub private_key: String,
}

/// Generate a P-521 key pair.
///
/// Returns a JS object: `{ publicKey: "age521...", privateKey: "AGE-SECRET-KEY-521-..." }`
#[wasm_bindgen]
pub fn keygen() -> Result<JsValue, JsValue> {
    let kp = KeyPair::generate();
    let result = KeyPairResult {
        public_key: encode_public_key(&kp.public),
        private_key: encode_secret_key(&kp.secret),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Encrypt `data` for `recipient_pubkey` (bech32-encoded P-521 public key).
///
/// Returns the encrypted file as an ASCII-armored string.
#[wasm_bindgen]
pub fn encrypt(recipient_pubkey: &str, data: &[u8]) -> Result<String, JsValue> {
    let ct = mobi521_core::encrypt(recipient_pubkey, data)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(mobi521_core::armor::armor(&ct))
}

/// Decrypt `data` using `private_key` (bech32-encoded P-521 secret key).
///
/// Returns the plaintext as a `Uint8Array`.
#[wasm_bindgen]
pub fn decrypt(private_key: &str, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    mobi521_core::decrypt(private_key, data)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Sign `message` with `private_key` (bech32-encoded P-521 secret key).
///
/// Returns a base64-encoded ECDSA-P521-SHA512 signature string.
#[wasm_bindgen]
pub fn sign(private_key: &str, message: &[u8]) -> Result<String, JsValue> {
    mobi521_core::sign(private_key, message)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify a signature against `message` using `public_key` (bech32-encoded P-521 public key).
///
/// Returns `true` if valid, throws a JS error if invalid.
#[wasm_bindgen]
pub fn verify(public_key: &str, message: &[u8], signature_b64: &str) -> Result<bool, JsValue> {
    mobi521_core::verify(public_key, message, signature_b64)
        .map(|_| true)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
