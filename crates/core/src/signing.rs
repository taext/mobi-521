use base64ct::{Base64, Encoding};
use elliptic_curve::sec1::ToEncodedPoint;
use p521::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    PublicKey, SecretKey,
};

use crate::Error;

/// Domain tag prepended to every message before signing/verifying.
/// Provides protocol separation so mobi-521 signatures are distinct from any
/// other ECDSA-P521-SHA512 signatures over the same raw bytes.
/// The trailing null byte prevents a crafted message from spoofing the prefix.
const SIGN_DOMAIN: &[u8] = b"mobi-521-sign-v1\x00";

fn tagged_message(message: &[u8]) -> Vec<u8> {
    let mut tagged = Vec::with_capacity(SIGN_DOMAIN.len() + message.len());
    tagged.extend_from_slice(SIGN_DOMAIN);
    tagged.extend_from_slice(message);
    tagged
}

/// Sign `message` with a P-521 secret key using ECDSA-SHA512 (hedged nonce).
/// Returns a base64-encoded fixed-size signature (r ‖ s, 132 bytes).
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<String, Error> {
    let signing_key = SigningKey::from_slice(secret_key.to_bytes().as_ref())
        .map_err(|e| Error::Signing(e.to_string()))?;

    let tagged = tagged_message(message);
    let signature: Signature = signing_key
        .try_sign(&tagged)
        .map_err(|e| Error::Signing(e.to_string()))?;

    Ok(Base64::encode_string(signature.to_bytes().as_ref()))
}

/// Verify a base64-encoded ECDSA-SHA512 signature against `message`.
/// Returns `Ok(())` on success, `Err(InvalidSignature)` on failure.
pub fn verify(public_key: &PublicKey, message: &[u8], signature_b64: &str) -> Result<(), Error> {
    let sig_bytes = Base64::decode_vec(signature_b64)
        .map_err(|_| Error::InvalidSignature("invalid base64 encoding".into()))?;

    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    let encoded = public_key.to_encoded_point(false);
    let verifying_key = VerifyingKey::from_encoded_point(&encoded)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    let tagged = tagged_message(message);
    verifying_key
        .verify(&tagged, &signature)
        .map_err(|_| Error::InvalidSignature("signature does not match".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p521::SecretKey;
    use rand::rngs::OsRng;

    fn generate_key() -> SecretKey {
        SecretKey::random(&mut OsRng)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = generate_key();
        let pk = sk.public_key();
        let sig = sign(&sk, b"test message").unwrap();
        verify(&pk, b"test message", &sig).unwrap();
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let sk = generate_key();
        let pk = sk.public_key();
        let sig = sign(&sk, b"original message").unwrap();
        assert!(verify(&pk, b"tampered message", &sig).is_err());
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        let sk = generate_key();
        let wrong_sk = generate_key();
        let wrong_pk = wrong_sk.public_key();
        let sig = sign(&sk, b"test").unwrap();
        assert!(verify(&wrong_pk, b"test", &sig).is_err());
    }

    #[test]
    fn signature_decodes_to_132_bytes() {
        let sk = generate_key();
        let sig_b64 = sign(&sk, b"length check").unwrap();
        let bytes = Base64::decode_vec(&sig_b64).unwrap();
        assert_eq!(bytes.len(), 132);
    }

    #[test]
    fn verify_fails_on_invalid_base64() {
        let sk = generate_key();
        let pk = sk.public_key();
        assert!(verify(&pk, b"msg", "not!!valid!!base64").is_err());
    }

    #[test]
    fn domain_tag_prevents_cross_protocol_reuse() {
        // A raw ECDSA signature over the message bytes (without domain tag)
        // must not verify under mobi-521's tagged scheme.
        use p521::ecdsa::signature::Signer;
        let sk = generate_key();
        let pk = sk.public_key();
        let signing_key = SigningKey::from_slice(sk.to_bytes().as_ref()).unwrap();
        let message = b"cross protocol test";
        // Sign the raw message (no domain tag)
        let raw_sig: Signature = signing_key.try_sign(message).unwrap();
        let raw_b64 = Base64::encode_string(raw_sig.to_bytes().as_ref());
        // mobi-521 verify must reject it (it would verify the tagged version)
        assert!(verify(&pk, message, &raw_b64).is_err());
    }
}
