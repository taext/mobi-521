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
