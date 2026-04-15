use bech32::{FromBase32, ToBase32, Variant};
use elliptic_curve::sec1::ToEncodedPoint;
use p521::{PublicKey, SecretKey};
use rand::rngs::OsRng;

use crate::Error;

/// bech32 HRP for public keys  →  `mobi521...`
pub const PUB_HRP: &str = "mobi521";

/// bech32 HRP for private keys →  `MOBI521-SECRET-KEY-...` (displayed uppercase)
pub const SEC_HRP: &str = "mobi521-secret-key";

pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        Self { public, secret }
    }
}

/// Encode a P-521 public key as a bech32m string.
/// The key is SEC1 compressed (67 bytes: 1 prefix + 66 x-coord bytes).
pub fn encode_public_key(key: &PublicKey) -> String {
    let point = key.to_encoded_point(true); // compressed
    let bytes = point.as_bytes();
    bech32::encode(PUB_HRP, bytes.to_base32(), Variant::Bech32m)
        .expect("bech32 encode cannot fail for valid inputs")
}

/// Decode a bech32m-encoded P-521 public key.
pub fn decode_public_key(s: &str) -> Result<PublicKey, Error> {
    let lower = s.to_lowercase();
    let (hrp, data, variant) =
        bech32::decode(&lower).map_err(|e| Error::InvalidKey(e.to_string()))?;
    if variant != Variant::Bech32m {
        return Err(Error::InvalidKey("key must be bech32m encoded".into()));
    }
    if hrp != PUB_HRP {
        return Err(Error::InvalidKey(format!(
            "wrong HRP: expected '{}', got '{}'",
            PUB_HRP, hrp
        )));
    }
    let bytes =
        Vec::<u8>::from_base32(&data).map_err(|e| Error::InvalidKey(e.to_string()))?;
    PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error::InvalidKey(e.to_string()))
}

/// Encode a P-521 secret key as a bech32m string (uppercase, like age).
pub fn encode_secret_key(key: &SecretKey) -> String {
    let bytes = key.to_bytes();
    let encoded =
        bech32::encode(SEC_HRP, bytes.as_slice().to_base32(), Variant::Bech32m)
            .expect("bech32 encode cannot fail for valid inputs");
    encoded.to_uppercase()
}

/// Decode a bech32m-encoded P-521 secret key.
/// Accepts both upper- and lower-case input.
pub fn decode_secret_key(s: &str) -> Result<SecretKey, Error> {
    let lower = s.to_lowercase();
    let (hrp, data, variant) =
        bech32::decode(&lower).map_err(|e| Error::InvalidKey(e.to_string()))?;
    if variant != Variant::Bech32m {
        return Err(Error::InvalidKey("key must be bech32m encoded".into()));
    }
    if hrp != SEC_HRP {
        return Err(Error::InvalidKey(format!(
            "wrong HRP: expected '{}', got '{}'",
            SEC_HRP, hrp
        )));
    }
    let bytes =
        Vec::<u8>::from_base32(&data).map_err(|e| Error::InvalidKey(e.to_string()))?;
    SecretKey::from_slice(&bytes).map_err(|e| Error::InvalidKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_encode_decode_roundtrip() {
        let kp = KeyPair::generate();
        let encoded = encode_public_key(&kp.public);
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(
            kp.public.to_encoded_point(true).as_bytes(),
            decoded.to_encoded_point(true).as_bytes()
        );
    }

    #[test]
    fn secret_key_encode_decode_roundtrip() {
        let kp = KeyPair::generate();
        let encoded = encode_secret_key(&kp.secret);
        let decoded = decode_secret_key(&encoded).unwrap();
        assert_eq!(
            kp.secret.to_bytes().as_slice(),
            decoded.to_bytes().as_slice()
        );
    }

    #[test]
    fn decode_public_key_rejects_secret_key_hrp() {
        let kp = KeyPair::generate();
        let sec_encoded = encode_secret_key(&kp.secret);
        let err = decode_public_key(&sec_encoded).unwrap_err();
        assert!(err.to_string().contains("wrong HRP"));
    }

    #[test]
    fn decode_secret_key_rejects_public_key_hrp() {
        let kp = KeyPair::generate();
        let pub_encoded = encode_public_key(&kp.public);
        let err = decode_secret_key(&pub_encoded).unwrap_err();
        assert!(err.to_string().contains("wrong HRP"));
    }

    #[test]
    fn decode_public_key_case_insensitive() {
        let kp = KeyPair::generate();
        let encoded = encode_public_key(&kp.public);
        decode_public_key(&encoded.to_uppercase()).unwrap();
    }

    #[test]
    fn secret_key_is_encoded_uppercase() {
        let kp = KeyPair::generate();
        let encoded = encode_secret_key(&kp.secret);
        assert_eq!(encoded, encoded.to_uppercase());
    }

    #[test]
    fn derived_public_key_matches_keypair() {
        let kp = KeyPair::generate();
        let derived = kp.secret.public_key();
        assert_eq!(
            kp.public.to_encoded_point(true).as_bytes(),
            derived.to_encoded_point(true).as_bytes()
        );
    }

    // ========================================================================
    // Security Tests - Invalid Key Rejection
    // ========================================================================

    #[test]
    fn rejects_truncated_public_key() {
        let kp = KeyPair::generate();
        let encoded = encode_public_key(&kp.public);
        // Remove last 5 characters (truncated key)
        let truncated = &encoded[..encoded.len() - 5];
        assert!(
            decode_public_key(truncated).is_err(),
            "truncated public key must be rejected"
        );
    }

    #[test]
    fn rejects_corrupted_public_key_checksum() {
        let kp = KeyPair::generate();
        let mut encoded = encode_public_key(&kp.public);
        // Corrupt the last character (part of checksum)
        let last_char = encoded.pop().unwrap();
        let new_char = if last_char == 'q' { 'p' } else { 'q' };
        encoded.push(new_char);
        assert!(
            decode_public_key(&encoded).is_err(),
            "corrupted checksum must be rejected"
        );
    }

    #[test]
    fn rejects_wrong_length_public_key_bytes() {
        // Construct a bech32m string with wrong byte length
        // Valid P-521 compressed point is 67 bytes, try 66 bytes
        let short_bytes = vec![0x02u8; 66]; // wrong length
        let encoded = bech32::encode(PUB_HRP, short_bytes.to_base32(), Variant::Bech32m)
            .unwrap();
        assert!(
            decode_public_key(&encoded).is_err(),
            "wrong length public key must be rejected"
        );
    }

    #[test]
    fn rejects_invalid_point_prefix() {
        // Valid SEC1 compressed prefix is 0x02 or 0x03
        // 0x04 is uncompressed, 0x00 is invalid
        let mut invalid_bytes = vec![0x00u8]; // invalid prefix
        invalid_bytes.extend(vec![0x42u8; 66]); // 66 bytes of x-coordinate
        let encoded = bech32::encode(PUB_HRP, invalid_bytes.to_base32(), Variant::Bech32m)
            .unwrap();
        assert!(
            decode_public_key(&encoded).is_err(),
            "invalid point prefix must be rejected"
        );
    }

    #[test]
    fn rejects_x_coordinate_exceeding_field_modulus() {
        // Construct a point with x-coordinate >= p (the field modulus)
        // P-521's p = 2^521 - 1 = 0x01FFFFFFFFFFFFFF... (all bits set except top 7)
        // Any x >= p is invalid
        let mut invalid_point = vec![0x02u8]; // valid compressed prefix
        // x = 2^521 (all 0xFF bytes = definitely >= p)
        invalid_point.extend(vec![0xFFu8; 66]);
        assert_eq!(invalid_point.len(), 67);

        let encoded = bech32::encode(PUB_HRP, invalid_point.to_base32(), Variant::Bech32m)
            .unwrap();

        assert!(
            decode_public_key(&encoded).is_err(),
            "x-coordinate exceeding field modulus must be rejected"
        );
    }

    #[test]
    fn rejects_random_invalid_point_bytes() {
        // Test with a known value that is NOT a valid point
        // Using x = 0x123456... (arbitrary) which statistically has ~50% chance
        // of not being on curve. We test multiple values to ensure at least one fails.
        let test_values: &[u8] = &[0x37, 0x73, 0xAB, 0xCD, 0xEF];
        let mut found_invalid = false;

        for &val in test_values {
            let mut test_point = vec![0x02u8];
            test_point.extend(vec![val; 66]);
            let encoded = bech32::encode(PUB_HRP, test_point.to_base32(), Variant::Bech32m)
                .unwrap();
            if decode_public_key(&encoded).is_err() {
                found_invalid = true;
                break;
            }
        }

        assert!(
            found_invalid,
            "at least one random x-coordinate should not be on the curve"
        );
    }

    #[test]
    fn rejects_bech32_not_bech32m() {
        // Encode with bech32 (not bech32m) variant
        let kp = KeyPair::generate();
        let point = kp.public.to_encoded_point(true);
        let bytes = point.as_bytes();
        let bech32_encoded = bech32::encode(PUB_HRP, bytes.to_base32(), Variant::Bech32)
            .unwrap();
        assert!(
            decode_public_key(&bech32_encoded).is_err(),
            "bech32 (not bech32m) must be rejected"
        );
    }

    #[test]
    fn rejects_empty_public_key() {
        assert!(
            decode_public_key("").is_err(),
            "empty string must be rejected"
        );
    }

    #[test]
    fn rejects_garbage_input() {
        assert!(
            decode_public_key("not-a-valid-key-at-all!!!").is_err(),
            "garbage input must be rejected"
        );
    }

    #[test]
    fn rejects_zero_secret_key() {
        // All-zero scalar is invalid for P-521
        let zero_bytes = vec![0x00u8; 66];
        let encoded = bech32::encode(SEC_HRP, zero_bytes.to_base32(), Variant::Bech32m)
            .unwrap()
            .to_uppercase();
        assert!(
            decode_secret_key(&encoded).is_err(),
            "zero secret key must be rejected"
        );
    }

    #[test]
    fn rejects_secret_key_exceeding_curve_order() {
        // P-521 order n is slightly less than 2^521
        // All 0xFF bytes would exceed the curve order
        let overflow_bytes = vec![0xFFu8; 66];
        let encoded = bech32::encode(SEC_HRP, overflow_bytes.to_base32(), Variant::Bech32m)
            .unwrap()
            .to_uppercase();
        assert!(
            decode_secret_key(&encoded).is_err(),
            "secret key exceeding curve order must be rejected"
        );
    }
}
