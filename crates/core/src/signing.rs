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

/// Sign `message` with a P-521 secret key using ECDSA-SHA512 (RFC 6979 deterministic).
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
