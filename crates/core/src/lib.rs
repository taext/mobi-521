pub mod armor;
pub mod crypto;
#[cfg(test)]
mod crypto_vectors;
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

#[cfg(test)]
mod tests {
    use super::*;
    use keys::{encode_public_key, encode_secret_key, KeyPair};

    fn generate_pair() -> (String, String) {
        let kp = KeyPair::generate();
        (encode_public_key(&kp.public), encode_secret_key(&kp.secret))
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (pub_key, sec_key) = generate_pair();
        let plaintext = b"hello, mobi-521!";
        let ciphertext = encrypt(&pub_key, plaintext).unwrap();
        let recovered = decrypt(&sec_key, &ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let (pub_key, sec_key) = generate_pair();
        let ciphertext = encrypt(&pub_key, b"").unwrap();
        let recovered = decrypt(&sec_key, &ciphertext).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn encrypt_decrypt_large_plaintext() {
        let (pub_key, sec_key) = generate_pair();
        // 200 KiB — forces multiple 64 KiB STREAM chunks
        let plaintext = vec![0xABu8; 200 * 1024];
        let ciphertext = encrypt(&pub_key, &plaintext).unwrap();
        let recovered = decrypt(&sec_key, &ciphertext).unwrap();
        assert_eq!(plaintext, recovered);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let (pub_key, _) = generate_pair();
        let (_, wrong_sec_key) = generate_pair();
        let ciphertext = encrypt(&pub_key, b"secret").unwrap();
        assert!(decrypt(&wrong_sec_key, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_accepts_armored_input() {
        let (pub_key, sec_key) = generate_pair();
        let plaintext = b"armored roundtrip";
        let raw = encrypt(&pub_key, plaintext).unwrap();
        let armored = armor::armor(&raw);
        let recovered = decrypt(&sec_key, armored.as_bytes()).unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let (pub_key, sec_key) = generate_pair();
        let mut ct = encrypt(&pub_key, b"data").unwrap();
        ct.truncate(ct.len() / 2);
        assert!(decrypt(&sec_key, &ct).is_err());
    }

    #[test]
    fn decrypt_rejects_corrupted_payload() {
        let (pub_key, sec_key) = generate_pair();
        let mut ct = encrypt(&pub_key, b"data to corrupt").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt(&sec_key, &ct).is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let pub_str = encode_public_key(&kp.public);
        let sec_str = encode_secret_key(&kp.secret);
        let message = b"sign this";
        let sig = sign(&sec_str, message).unwrap();
        verify(&pub_str, message, &sig).unwrap();
    }

    #[test]
    fn verify_fails_on_different_message() {
        let kp = KeyPair::generate();
        let pub_str = encode_public_key(&kp.public);
        let sec_str = encode_secret_key(&kp.secret);
        let sig = sign(&sec_str, b"original").unwrap();
        assert!(verify(&pub_str, b"different", &sig).is_err());
    }

    #[test]
    fn encrypt_output_starts_with_magic() {
        let (pub_key, _) = generate_pair();
        let ct = encrypt(&pub_key, b"test").unwrap();
        assert!(ct.starts_with(format::MAGIC.as_bytes()));
    }
}
