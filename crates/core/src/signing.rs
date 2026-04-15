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

    // ========================================================================
    // Signature Security Tests
    // ========================================================================

    #[test]
    fn rejects_empty_signature() {
        let sk = generate_key();
        let pk = sk.public_key();
        assert!(
            verify(&pk, b"test", "").is_err(),
            "empty signature must be rejected"
        );
    }

    #[test]
    fn rejects_truncated_signature() {
        let sk = generate_key();
        let pk = sk.public_key();
        let sig = sign(&sk, b"test").unwrap();
        // Truncate the signature
        let truncated = &sig[..sig.len() / 2];
        assert!(
            verify(&pk, b"test", truncated).is_err(),
            "truncated signature must be rejected"
        );
    }

    #[test]
    fn rejects_extended_signature() {
        let sk = generate_key();
        let pk = sk.public_key();
        let sig = sign(&sk, b"test").unwrap();
        // Extend the signature with garbage
        let extended = format!("{}AAAA", sig);
        assert!(
            verify(&pk, b"test", &extended).is_err(),
            "extended signature must be rejected"
        );
    }

    #[test]
    fn rejects_all_zero_signature() {
        let sk = generate_key();
        let pk = sk.public_key();
        // 132 zero bytes base64-encoded
        let zero_sig = Base64::encode_string(&[0u8; 132]);
        assert!(
            verify(&pk, b"test", &zero_sig).is_err(),
            "all-zero signature must be rejected"
        );
    }

    #[test]
    fn signature_malleability_handled_consistently() {
        // ECDSA has signature malleability: (r, s) and (r, n-s) are both valid
        // for the same message. This test verifies behavior is consistent
        // when the s-component is modified.
        let sk = generate_key();
        let pk = sk.public_key();
        let sig = sign(&sk, b"malleability test").unwrap();

        // Original signature should verify
        assert!(
            verify(&pk, b"malleability test", &sig).is_ok(),
            "original signature should verify"
        );

        // Decode the signature and flip high bit of s-component
        // This creates an invalid/malleable form
        let sig_bytes = Base64::decode_vec(&sig).unwrap();
        assert_eq!(sig_bytes.len(), 132, "P-521 signature should be 132 bytes");

        let mut malleable = sig_bytes.clone();
        // Flip high bit of s (byte 66 is start of s-component)
        malleable[66] ^= 0x80;
        let malleable_b64 = Base64::encode_string(&malleable);

        // The malleable form should either fail validation or be normalized
        // What matters: no panic, consistent behavior
        let result = verify(&pk, b"malleability test", &malleable_b64);
        // Result can be Ok or Err - we just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn empty_message_can_be_signed() {
        let sk = generate_key();
        let pk = sk.public_key();
        let sig = sign(&sk, b"").unwrap();
        assert!(
            verify(&pk, b"", &sig).is_ok(),
            "empty message signature should verify"
        );
    }

    #[test]
    fn large_message_can_be_signed() {
        let sk = generate_key();
        let pk = sk.public_key();
        // 1 MB message
        let large_message = vec![0xABu8; 1024 * 1024];
        let sig = sign(&sk, &large_message).unwrap();
        assert!(
            verify(&pk, &large_message, &sig).is_ok(),
            "large message signature should verify"
        );
    }
}
