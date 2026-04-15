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
/// Returns a JS object: `{ publicKey: "mobi521...", privateKey: "MOBI521-SECRET-KEY-..." }`
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // ========================================================================
    // Keygen tests
    // ========================================================================

    #[wasm_bindgen_test]
    fn keygen_returns_valid_keypair() {
        let result = keygen().expect("keygen should succeed");

        // Convert JsValue to KeyPairResult
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(result)
            .expect("should deserialize to KeyPairResult");

        // Check public key format
        assert!(kp.public_key.starts_with("mobi5211"), "public key should start with mobi5211");

        // Check private key format (bech32 uses '1' as separator)
        assert!(kp.private_key.starts_with("MOBI521-SECRET-KEY1"), "private key should start with MOBI521-SECRET-KEY1");
    }

    #[wasm_bindgen_test]
    fn keygen_generates_unique_keys() {
        let kp1: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();
        let kp2: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        assert_ne!(kp1.public_key, kp2.public_key, "should generate different public keys");
        assert_ne!(kp1.private_key, kp2.private_key, "should generate different private keys");
    }

    // ========================================================================
    // Encrypt/Decrypt tests
    // ========================================================================

    #[wasm_bindgen_test]
    fn encrypt_decrypt_roundtrip() {
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let plaintext = b"Hello, WASM mobi-521!";
        let ciphertext = encrypt(&kp.public_key, plaintext).expect("encrypt should succeed");

        // Verify ciphertext is armored
        assert!(ciphertext.contains("-----BEGIN MOBI-521 ENCRYPTED FILE-----"));
        assert!(ciphertext.contains("-----END MOBI-521 ENCRYPTED FILE-----"));

        // Decrypt
        let decrypted = decrypt(&kp.private_key, ciphertext.as_bytes())
            .expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn encrypt_decrypt_empty_plaintext() {
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let plaintext = b"";
        let ciphertext = encrypt(&kp.public_key, plaintext).expect("encrypt should succeed");
        let decrypted = decrypt(&kp.private_key, ciphertext.as_bytes())
            .expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn encrypt_decrypt_binary_data() {
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        // All byte values 0-255
        let plaintext: Vec<u8> = (0..=255).collect();
        let ciphertext = encrypt(&kp.public_key, &plaintext).expect("encrypt should succeed");
        let decrypted = decrypt(&kp.private_key, ciphertext.as_bytes())
            .expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn decrypt_fails_with_wrong_key() {
        let kp1: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();
        let kp2: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let plaintext = b"secret message";
        let ciphertext = encrypt(&kp1.public_key, plaintext).expect("encrypt should succeed");

        // Try to decrypt with wrong key
        let result = decrypt(&kp2.private_key, ciphertext.as_bytes());
        assert!(result.is_err(), "decrypt with wrong key should fail");
    }

    #[wasm_bindgen_test]
    fn encrypt_fails_with_invalid_pubkey() {
        let result = encrypt("invalid-key", b"test");
        assert!(result.is_err(), "encrypt with invalid pubkey should fail");
    }

    #[wasm_bindgen_test]
    fn decrypt_fails_with_invalid_ciphertext() {
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let result = decrypt(&kp.private_key, b"not valid ciphertext");
        assert!(result.is_err(), "decrypt with invalid ciphertext should fail");
    }

    // ========================================================================
    // Sign/Verify tests
    // ========================================================================

    #[wasm_bindgen_test]
    fn sign_verify_roundtrip() {
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let message = b"Message to sign";
        let signature = sign(&kp.private_key, message).expect("sign should succeed");

        // Signature should be base64-encoded
        assert!(!signature.is_empty());
        assert!(signature.len() >= 170, "P-521 signature should be ~176 base64 chars");

        // Verify
        let result = verify(&kp.public_key, message, &signature)
            .expect("verify should succeed");
        assert!(result, "signature should be valid");
    }

    #[wasm_bindgen_test]
    fn verify_fails_on_tampered_message() {
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let message = b"Original message";
        let signature = sign(&kp.private_key, message).expect("sign should succeed");

        // Verify with tampered message
        let tampered = b"Tampered message";
        let result = verify(&kp.public_key, tampered, &signature);
        assert!(result.is_err(), "verify with tampered message should fail");
    }

    #[wasm_bindgen_test]
    fn verify_fails_with_wrong_key() {
        let kp1: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();
        let kp2: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let message = b"Test message";
        let signature = sign(&kp1.private_key, message).expect("sign should succeed");

        // Verify with wrong public key
        let result = verify(&kp2.public_key, message, &signature);
        assert!(result.is_err(), "verify with wrong key should fail");
    }

    #[wasm_bindgen_test]
    fn sign_fails_with_invalid_key() {
        let result = sign("invalid-key", b"test");
        assert!(result.is_err(), "sign with invalid key should fail");
    }

    #[wasm_bindgen_test]
    fn verify_fails_with_invalid_signature() {
        let kp: KeyPairResult = serde_wasm_bindgen::from_value(keygen().unwrap()).unwrap();

        let result = verify(&kp.public_key, b"test", "not-valid-base64!!!");
        assert!(result.is_err(), "verify with invalid signature should fail");
    }
}
