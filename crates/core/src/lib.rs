pub mod armor;
pub mod crypto;
pub mod format;
pub mod keys;
pub mod signing;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("format error: {0}")]
    Format(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

/// Encrypt `plaintext` for `recipient_pubkey` (bech32-encoded).
/// Returns the full encrypted file as bytes.
pub fn encrypt(recipient_pubkey: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    use rand::RngCore;
    use rand::rngs::OsRng;
    use zeroize::Zeroizing;

    let recipient = keys::decode_public_key(recipient_pubkey)?;

    // Generate a random 32-byte file key
    let mut file_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(file_key.as_mut());

    // Wrap the file key for the recipient
    let wrapped = crypto::wrap_file_key(&*file_key, &recipient);

    // Encrypt the payload
    let payload = crypto::encrypt_payload(&*file_key, plaintext);

    // Serialise to the age-512 format
    let mut out = Vec::new();
    format::write_encrypted(&mut out, &wrapped, &payload)?;
    Ok(out)
}

/// Sign `message` with `secret_key` (bech32-encoded).
/// Returns a base64-encoded ECDSA-P521-SHA512 signature.
pub fn sign(secret_key: &str, message: &[u8]) -> Result<String, Error> {
    let sk = keys::decode_secret_key(secret_key)?;
    signing::sign(&sk, message)
}

/// Verify a base64-encoded signature against `message` using `public_key` (bech32-encoded).
/// Returns Ok(()) if valid, Err if not.
pub fn verify(public_key: &str, message: &[u8], signature_b64: &str) -> Result<(), Error> {
    let pk = keys::decode_public_key(public_key)?;
    signing::verify(&pk, message, signature_b64)
}

/// Decrypt `ciphertext` using `secret_key` (bech32-encoded).
/// Accepts both raw binary and ASCII-armored input.
pub fn decrypt(secret_key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let sk = keys::decode_secret_key(secret_key)?;

    let raw: std::borrow::Cow<[u8]> = if armor::is_armored(ciphertext) {
        armor::dearmor(ciphertext)?.into()
    } else {
        ciphertext.into()
    };

    // Parse header + payload
    let ef = format::parse_encrypted(&raw)?;

    // Decode ephemeral public key
    let ephemeral_pub = keys::decode_public_key(&ef.ephemeral_pub_encoded)?;

    // Reconstruct the recipient
    let recipient = crypto::WrappedKey {
        ephemeral_pub,
        encrypted_file_key: ef.enc_file_key,
    };

    // Unwrap the file key
    let file_key = zeroize::Zeroizing::new(crypto::unwrap_file_key(&recipient, &sk)?);

    // Decrypt the payload
    crypto::decrypt_payload(&*file_key, &ef.payload)
}
