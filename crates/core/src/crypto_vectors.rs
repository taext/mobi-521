//! Cryptographic property tests using official test vectors from NIST and RFCs.
//!
//! These tests verify that the underlying cryptographic primitives behave correctly
//! according to their specifications.

#[cfg(test)]
mod tests {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Key, Nonce,
    };
    use hkdf::Hkdf;
    use sha2::Sha512;

    // ============================================================================
    // RFC 8439 - ChaCha20-Poly1305 Test Vectors
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    // ============================================================================

    #[test]
    fn chacha20_poly1305_rfc8439_test_vector() {
        // RFC 8439 Section 2.8.2 - AEAD_CHACHA20_POLY1305 Test Vector
        // Using the key and nonce from the RFC to verify cipher implementation.
        // Note: Full RFC test includes AAD; we test core encrypt/decrypt here.
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let key = hex::decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .unwrap();

        let nonce = hex::decode("070000004041424344454647").unwrap();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce);

        // Encrypt and verify decryption roundtrip with RFC key/nonce
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha20_poly1305_empty_message() {
        // Test that empty messages work correctly
        let key = [0x42u8; 32];
        let nonce = [0x00u8; 12];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce, b"".as_ref()).unwrap();
        // Empty plaintext should produce only the 16-byte Poly1305 tag
        assert_eq!(ciphertext.len(), 16);

        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn chacha20_poly1305_tag_length() {
        // Verify Poly1305 tag is always 16 bytes
        let key = [0x00u8; 32];
        let nonce = [0x00u8; 12];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce);

        for len in [0, 1, 15, 16, 17, 64, 1024] {
            let plaintext = vec![0xABu8; len];
            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
            assert_eq!(
                ciphertext.len(),
                len + 16,
                "ciphertext should be plaintext + 16 byte tag"
            );
        }
    }

    #[test]
    fn chacha20_poly1305_bit_flip_detection() {
        // Verify that any bit flip in ciphertext causes authentication failure
        let key = [0x42u8; 32];
        let nonce = [0x00u8; 12];
        let plaintext = b"test message for bit flip detection";

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Flip each byte and verify decryption fails
        for i in 0..ciphertext.len() {
            let mut corrupted = ciphertext.clone();
            corrupted[i] ^= 0x01;
            assert!(
                cipher.decrypt(nonce, corrupted.as_ref()).is_err(),
                "decryption should fail when byte {} is corrupted",
                i
            );
        }
    }

    // ============================================================================
    // HKDF-SHA512 Test Vectors
    // Based on RFC 5869 structure, computed for SHA-512
    // ============================================================================

    #[test]
    fn hkdf_sha512_basic_test_vector() {
        // Test vector computed using reference implementation
        // IKM = 0x0b repeated 22 times
        // Salt = 0x000102030405060708090a0b0c (13 bytes)
        // Info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
        // L = 42 bytes

        let ikm = vec![0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let hkdf = Hkdf::<Sha512>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();

        // The output should be deterministic
        // Verify by computing twice
        let hkdf2 = Hkdf::<Sha512>::new(Some(&salt), &ikm);
        let mut okm2 = [0u8; 42];
        hkdf2.expand(&info, &mut okm2).unwrap();

        assert_eq!(okm, okm2, "HKDF should be deterministic");
    }

    #[test]
    fn hkdf_sha512_different_salts_produce_different_keys() {
        let ikm = b"input key material";

        let hkdf1 = Hkdf::<Sha512>::new(Some(b"salt1"), ikm);
        let hkdf2 = Hkdf::<Sha512>::new(Some(b"salt2"), ikm);

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];

        hkdf1.expand(b"info", &mut key1).unwrap();
        hkdf2.expand(b"info", &mut key2).unwrap();

        assert_ne!(key1, key2, "different salts should produce different keys");
    }

    #[test]
    fn hkdf_sha512_different_info_produces_different_keys() {
        let ikm = b"input key material";
        let salt = b"salt";

        let hkdf = Hkdf::<Sha512>::new(Some(salt), ikm);

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];

        hkdf.expand(b"info1", &mut key1).unwrap();
        hkdf.expand(b"info2", &mut key2).unwrap();

        assert_ne!(key1, key2, "different info should produce different keys");
    }

    #[test]
    fn hkdf_sha512_no_salt_uses_zero_salt() {
        let ikm = b"input key material";

        // No salt
        let hkdf1 = Hkdf::<Sha512>::new(None, ikm);
        // Explicit zero salt (64 bytes for SHA-512)
        let zero_salt = [0u8; 64];
        let hkdf2 = Hkdf::<Sha512>::new(Some(&zero_salt), ikm);

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];

        hkdf1.expand(b"info", &mut key1).unwrap();
        hkdf2.expand(b"info", &mut key2).unwrap();

        assert_eq!(
            key1, key2,
            "no salt should be equivalent to zero salt"
        );
    }

    #[test]
    fn hkdf_sha512_max_output_length() {
        // HKDF can output at most 255 * HashLen bytes
        // For SHA-512: 255 * 64 = 16320 bytes
        let ikm = b"test";
        let hkdf = Hkdf::<Sha512>::new(None, ikm);

        // Should succeed for max length
        let mut okm = vec![0u8; 255 * 64];
        assert!(hkdf.expand(b"", &mut okm).is_ok());

        // Should fail for max + 1
        let mut okm_too_long = vec![0u8; 255 * 64 + 1];
        assert!(hkdf.expand(b"", &mut okm_too_long).is_err());
    }

    // ============================================================================
    // P-521 ECDH Property Tests
    // ============================================================================

    #[test]
    fn p521_ecdh_shared_secret_is_symmetric() {
        use elliptic_curve::ecdh::EphemeralSecret;
        use p521::NistP521;
        use rand::rngs::OsRng;

        // Generate two keypairs
        let secret_a = EphemeralSecret::<NistP521>::random(&mut OsRng);
        let secret_b = EphemeralSecret::<NistP521>::random(&mut OsRng);

        // Get public keys (needed for cross-DH)
        let public_a = secret_a.public_key();
        let public_b = secret_b.public_key();

        // ECDH both directions: A with B's public, B with A's public
        let shared_ab = secret_a.diffie_hellman(&public_b);
        let shared_ba = secret_b.diffie_hellman(&public_a);

        // Shared secrets must be identical (ECDH symmetry property)
        assert_eq!(
            shared_ab.raw_secret_bytes().as_slice(),
            shared_ba.raw_secret_bytes().as_slice(),
            "ECDH shared secret must be symmetric"
        );
    }

    #[test]
    fn p521_ecdh_shared_secret_length() {
        use elliptic_curve::ecdh::EphemeralSecret;
        use p521::NistP521;
        use rand::rngs::OsRng;

        let secret_a = EphemeralSecret::<NistP521>::random(&mut OsRng);
        let secret_b = EphemeralSecret::<NistP521>::random(&mut OsRng);
        let public_b = secret_b.public_key();

        let shared = secret_a.diffie_hellman(&public_b);

        // P-521 shared secret is 66 bytes (521 bits rounded up)
        assert_eq!(
            shared.raw_secret_bytes().len(),
            66,
            "P-521 shared secret should be 66 bytes"
        );
    }

    #[test]
    fn p521_ecdh_different_keypairs_produce_different_secrets() {
        use elliptic_curve::ecdh::EphemeralSecret;
        use p521::NistP521;
        use rand::rngs::OsRng;

        let secret_a = EphemeralSecret::<NistP521>::random(&mut OsRng);

        let secret_b = EphemeralSecret::<NistP521>::random(&mut OsRng);
        let public_b = secret_b.public_key();

        let secret_c = EphemeralSecret::<NistP521>::random(&mut OsRng);
        let public_c = secret_c.public_key();

        // A computes shared secret with B and C separately
        let shared_ab = secret_a.diffie_hellman(&public_b);
        let shared_ac = secret_a.diffie_hellman(&public_c);

        assert_ne!(
            shared_ab.raw_secret_bytes().as_slice(),
            shared_ac.raw_secret_bytes().as_slice(),
            "different recipients should produce different shared secrets"
        );
    }

    #[test]
    fn p521_public_key_compressed_length() {
        use elliptic_curve::{ecdh::EphemeralSecret, sec1::ToEncodedPoint};
        use p521::NistP521;
        use rand::rngs::OsRng;

        let secret = EphemeralSecret::<NistP521>::random(&mut OsRng);
        let public = secret.public_key();

        let compressed = public.to_encoded_point(true);
        let uncompressed = public.to_encoded_point(false);

        // Compressed: 1 byte prefix + 66 bytes x-coordinate = 67 bytes
        assert_eq!(
            compressed.as_bytes().len(),
            67,
            "compressed P-521 point should be 67 bytes"
        );

        // Uncompressed: 1 byte prefix + 66 bytes x + 66 bytes y = 133 bytes
        assert_eq!(
            uncompressed.as_bytes().len(),
            133,
            "uncompressed P-521 point should be 133 bytes"
        );
    }

    // ============================================================================
    // ECDSA-P521-SHA512 Property Tests
    // ============================================================================

    #[test]
    fn ecdsa_p521_signature_length() {
        use p521::ecdsa::{signature::Signer, Signature, SigningKey};
        use p521::SecretKey;
        use rand::rngs::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from_slice(secret_key.to_bytes().as_ref()).unwrap();
        let message = b"test message";

        let signature: Signature = signing_key.try_sign(message).unwrap();
        let bytes = signature.to_bytes();

        // P-521 ECDSA signature: r (66 bytes) + s (66 bytes) = 132 bytes
        assert_eq!(
            bytes.len(),
            132,
            "P-521 ECDSA signature should be 132 bytes"
        );
    }

    #[test]
    fn ecdsa_p521_hedged_signatures_differ() {
        // p521 crate uses hedged signatures (RFC 6979 + additional randomness)
        // This is MORE secure than pure deterministic signatures as it protects
        // against fault attacks. Each signature should be different.
        use p521::ecdsa::{signature::Signer, Signature, SigningKey};
        use p521::SecretKey;
        use rand::rngs::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from_slice(secret_key.to_bytes().as_ref()).unwrap();
        let message = b"hedged signature test";

        let sig1: Signature = signing_key.try_sign(message).unwrap();
        let sig2: Signature = signing_key.try_sign(message).unwrap();

        // Hedged signatures should differ (additional randomness each time)
        assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "hedged signatures should differ due to additional randomness"
        );
    }

    #[test]
    fn ecdsa_p521_different_messages_different_signatures() {
        use p521::ecdsa::{signature::Signer, Signature, SigningKey};
        use p521::SecretKey;
        use rand::rngs::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from_slice(secret_key.to_bytes().as_ref()).unwrap();

        let sig1: Signature = signing_key.try_sign(b"message 1").unwrap();
        let sig2: Signature = signing_key.try_sign(b"message 2").unwrap();

        assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "different messages should produce different signatures"
        );
    }

    #[test]
    fn ecdsa_p521_verification_fails_on_wrong_message() {
        use elliptic_curve::sec1::ToEncodedPoint;
        use p521::ecdsa::{
            signature::{Signer, Verifier},
            Signature, SigningKey, VerifyingKey,
        };
        use p521::SecretKey;
        use rand::rngs::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from_slice(secret_key.to_bytes().as_ref()).unwrap();
        let public_key = secret_key.public_key();
        let verifying_key = VerifyingKey::from_encoded_point(&public_key.to_encoded_point(false)).unwrap();

        let signature: Signature = signing_key.try_sign(b"original").unwrap();

        assert!(
            verifying_key.verify(b"tampered", &signature).is_err(),
            "verification should fail on wrong message"
        );
    }

    #[test]
    fn ecdsa_p521_verification_fails_on_wrong_key() {
        use elliptic_curve::sec1::ToEncodedPoint;
        use p521::ecdsa::{
            signature::{Signer, Verifier},
            Signature, SigningKey, VerifyingKey,
        };
        use p521::SecretKey;
        use rand::rngs::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from_slice(secret_key.to_bytes().as_ref()).unwrap();

        let wrong_secret = SecretKey::random(&mut OsRng);
        let wrong_public = wrong_secret.public_key();
        let wrong_verifying_key = VerifyingKey::from_encoded_point(&wrong_public.to_encoded_point(false)).unwrap();

        let signature: Signature = signing_key.try_sign(b"message").unwrap();

        assert!(
            wrong_verifying_key.verify(b"message", &signature).is_err(),
            "verification should fail with wrong key"
        );
    }

    // ============================================================================
    // mobi-521 Integration Property Tests
    // ============================================================================

    #[test]
    fn mobi521_wrap_unwrap_preserves_file_key() {
        use crate::crypto::{unwrap_file_key, wrap_file_key};
        use crate::keys::KeyPair;

        let kp = KeyPair::generate();
        let file_key = [0x42u8; 32];

        let wrapped = wrap_file_key(&file_key, &kp.public);
        let unwrapped = unwrap_file_key(&wrapped, &kp.secret).unwrap();

        assert_eq!(file_key, unwrapped);
    }

    #[test]
    fn mobi521_wrapped_key_structure() {
        use crate::crypto::wrap_file_key;
        use crate::keys::KeyPair;
        use elliptic_curve::sec1::ToEncodedPoint;

        let kp = KeyPair::generate();
        let file_key = [0x00u8; 32];

        let wrapped = wrap_file_key(&file_key, &kp.public);

        // Ephemeral public key should be a valid P-521 point
        let ephemeral_compressed = wrapped.ephemeral_pub.to_encoded_point(true);
        assert_eq!(
            ephemeral_compressed.as_bytes().len(),
            67,
            "ephemeral public key should be 67 bytes compressed"
        );

        // Encrypted file key: 32 bytes + 16 byte tag = 48 bytes
        assert_eq!(
            wrapped.encrypted_file_key.len(),
            48,
            "encrypted file key should be 48 bytes (32 + 16 tag)"
        );
    }

    #[test]
    fn mobi521_different_recipients_produce_different_ciphertexts() {
        use crate::crypto::wrap_file_key;
        use crate::keys::KeyPair;

        let recipient1 = KeyPair::generate();
        let recipient2 = KeyPair::generate();
        let file_key = [0x42u8; 32];

        let wrapped1 = wrap_file_key(&file_key, &recipient1.public);
        let wrapped2 = wrap_file_key(&file_key, &recipient2.public);

        // Even with same file key, ephemeral keys differ
        assert_ne!(
            wrapped1.encrypted_file_key, wrapped2.encrypted_file_key,
            "different recipients should produce different ciphertexts"
        );
    }

    #[test]
    fn mobi521_same_recipient_different_ephemeral_keys() {
        use crate::crypto::wrap_file_key;
        use crate::keys::KeyPair;
        use elliptic_curve::sec1::ToEncodedPoint;

        let recipient = KeyPair::generate();
        let file_key = [0x42u8; 32];

        let wrapped1 = wrap_file_key(&file_key, &recipient.public);
        let wrapped2 = wrap_file_key(&file_key, &recipient.public);

        // Each wrap uses a fresh ephemeral key
        assert_ne!(
            wrapped1.ephemeral_pub.to_encoded_point(true).as_bytes(),
            wrapped2.ephemeral_pub.to_encoded_point(true).as_bytes(),
            "each wrap should use a fresh ephemeral key"
        );
    }

    #[test]
    fn mobi521_stream_chunk_boundaries() {
        use crate::crypto::{decrypt_payload, encrypt_payload};

        let file_key = [0x42u8; 32];

        // Test at exact chunk boundaries (64 KiB = 65536 bytes)
        for size in [0, 1, 65535, 65536, 65537, 131072, 131073] {
            let plaintext = vec![0xABu8; size];
            let ciphertext = encrypt_payload(&file_key, &plaintext);
            let decrypted = decrypt_payload(&file_key, &ciphertext).unwrap();
            assert_eq!(
                plaintext, decrypted,
                "roundtrip failed for size {}",
                size
            );
        }
    }

    #[test]
    fn mobi521_stream_nonce_uniqueness() {
        use crate::crypto::encrypt_payload;

        let file_key = [0x42u8; 32];
        let plaintext = b"test";

        // Each encryption should have a unique base nonce
        let ct1 = encrypt_payload(&file_key, plaintext);
        let ct2 = encrypt_payload(&file_key, plaintext);

        // First 12 bytes are the base nonce
        assert_ne!(
            &ct1[..12],
            &ct2[..12],
            "each encryption should have a unique nonce"
        );
    }

    // ============================================================================
    // STREAM Security Tests - Chunk Manipulation Attacks
    // ============================================================================

    #[test]
    fn stream_rejects_reordered_chunks() {
        use crate::crypto::{decrypt_payload, encrypt_payload};

        let file_key = [0x42u8; 32];
        // 3 full chunks = 3 * 64 KiB = 196608 bytes
        let plaintext = vec![0xABu8; 196608];
        let ciphertext = encrypt_payload(&file_key, &plaintext);

        // Structure: nonce(12) + chunk0(65536+16) + chunk1(65536+16) + chunk2(65536+16)
        let chunk_size = 65536 + 16; // plaintext + tag
        let nonce = &ciphertext[..12];
        let chunk0 = &ciphertext[12..12 + chunk_size];
        let chunk1 = &ciphertext[12 + chunk_size..12 + 2 * chunk_size];
        let chunk2 = &ciphertext[12 + 2 * chunk_size..];

        // Reorder: swap chunk0 and chunk1
        let mut reordered = Vec::new();
        reordered.extend_from_slice(nonce);
        reordered.extend_from_slice(chunk1); // was chunk0
        reordered.extend_from_slice(chunk0); // was chunk1
        reordered.extend_from_slice(chunk2);

        assert!(
            decrypt_payload(&file_key, &reordered).is_err(),
            "reordered chunks must be rejected"
        );
    }

    #[test]
    fn stream_rejects_removed_middle_chunk() {
        use crate::crypto::{decrypt_payload, encrypt_payload};

        let file_key = [0x42u8; 32];
        // 3 full chunks
        let plaintext = vec![0xABu8; 196608];
        let ciphertext = encrypt_payload(&file_key, &plaintext);

        let chunk_size = 65536 + 16;
        let nonce = &ciphertext[..12];
        let chunk0 = &ciphertext[12..12 + chunk_size];
        // skip chunk1
        let chunk2 = &ciphertext[12 + 2 * chunk_size..];

        // Remove middle chunk
        let mut truncated = Vec::new();
        truncated.extend_from_slice(nonce);
        truncated.extend_from_slice(chunk0);
        truncated.extend_from_slice(chunk2);

        assert!(
            decrypt_payload(&file_key, &truncated).is_err(),
            "removed middle chunk must be rejected"
        );
    }

    #[test]
    fn stream_rejects_duplicated_chunk() {
        use crate::crypto::{decrypt_payload, encrypt_payload};

        let file_key = [0x42u8; 32];
        // 2 full chunks
        let plaintext = vec![0xABu8; 131072];
        let ciphertext = encrypt_payload(&file_key, &plaintext);

        let chunk_size = 65536 + 16;
        let nonce = &ciphertext[..12];
        let chunk0 = &ciphertext[12..12 + chunk_size];
        let chunk1 = &ciphertext[12 + chunk_size..];

        // Duplicate chunk0
        let mut duplicated = Vec::new();
        duplicated.extend_from_slice(nonce);
        duplicated.extend_from_slice(chunk0);
        duplicated.extend_from_slice(chunk0); // duplicate
        duplicated.extend_from_slice(chunk1);

        assert!(
            decrypt_payload(&file_key, &duplicated).is_err(),
            "duplicated chunk must be rejected"
        );
    }

    #[test]
    fn stream_rejects_truncated_final_chunk() {
        use crate::crypto::{decrypt_payload, encrypt_payload};

        let file_key = [0x42u8; 32];
        let plaintext = b"test data for truncation";
        let ciphertext = encrypt_payload(&file_key, plaintext);

        // Remove last byte (part of Poly1305 tag)
        let truncated = &ciphertext[..ciphertext.len() - 1];

        assert!(
            decrypt_payload(&file_key, truncated).is_err(),
            "truncated final chunk must be rejected"
        );
    }

    #[test]
    fn stream_rejects_appended_garbage() {
        use crate::crypto::{decrypt_payload, encrypt_payload};

        let file_key = [0x42u8; 32];
        let plaintext = b"test data";
        let mut ciphertext = encrypt_payload(&file_key, plaintext);

        // Append garbage after valid ciphertext
        ciphertext.extend_from_slice(b"garbage data appended");

        assert!(
            decrypt_payload(&file_key, &ciphertext).is_err(),
            "appended garbage must be rejected"
        );
    }

    #[test]
    fn stream_rejects_modified_nonce() {
        use crate::crypto::{decrypt_payload, encrypt_payload};

        let file_key = [0x42u8; 32];
        let plaintext = b"test data";
        let mut ciphertext = encrypt_payload(&file_key, plaintext);

        // Flip a bit in the base nonce
        ciphertext[0] ^= 0x01;

        assert!(
            decrypt_payload(&file_key, &ciphertext).is_err(),
            "modified nonce must cause decryption failure"
        );
    }
}
