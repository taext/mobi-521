use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use elliptic_curve::{ecdh::EphemeralSecret, sec1::ToEncodedPoint};
use hkdf::Hkdf;
use p521::{NistP521, PublicKey, SecretKey};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::Error;

const HKDF_INFO: &[u8] = b"mobi521.io/encrypted/v3";
const FILE_KEY_LEN: usize = 32;
/// Plaintext bytes per STREAM chunk (64 KiB, matching the age spec).
const CHUNK_SIZE: usize = 65536;

/// Derive the per-chunk nonce from `base` by XORing the counter into bytes
/// 8–11 and the is-final flag into byte 7.
///
/// Layout of the 12-byte nonce after XOR:
///   [0..7]  — base bytes (untouched by counter/flag)
///   [7]     — XOR'd with 0x01 for the final chunk, 0x00 otherwise
///   [8..12] — XOR'd with `counter` as big-endian u32
fn chunk_nonce(base: &[u8; 12], counter: u32, is_final: bool) -> Nonce {
    let mut n = *base;
    n[7] ^= if is_final { 1u8 } else { 0u8 };
    let cb = counter.to_be_bytes();
    n[8] ^= cb[0];
    n[9] ^= cb[1];
    n[10] ^= cb[2];
    n[11] ^= cb[3];
    Nonce::from(n)
}

/// The wrapped file key and the ephemeral public key needed to unwrap it.
pub struct WrappedKey {
    pub ephemeral_pub: PublicKey,
    /// ChaCha20-Poly1305 ciphertext of the 32-byte file key (48 bytes: 32 + 16 tag)
    pub encrypted_file_key: Vec<u8>,
}

/// Wrap a file key for a recipient using ephemeral ECDH + HKDF + ChaCha20-Poly1305.
///
/// Scheme:
///   shared  = ECDH(ephemeral_priv, recipient_pub)          // 66-byte x-coord
///   salt    = compressed(ephemeral_pub) || compressed(recipient_pub)
///   wrapkey = HKDF-SHA512(ikm=shared, salt=salt, info=HKDF_INFO)[..32]
///   enc_fk  = ChaCha20-Poly1305(key=wrapkey, nonce=0, pt=file_key)
pub fn wrap_file_key(file_key: &[u8; FILE_KEY_LEN], recipient_pub: &PublicKey) -> WrappedKey {
    // Ephemeral keypair
    let ephemeral = EphemeralSecret::<NistP521>::random(&mut OsRng);
    let ephemeral_pub = ephemeral.public_key();

    // ECDH
    let shared = ephemeral.diffie_hellman(recipient_pub);

    // Build HKDF salt from both compressed public keys
    let ephem_enc = ephemeral_pub.to_encoded_point(true);
    let recip_enc = recipient_pub.to_encoded_point(true);
    let mut salt = Vec::with_capacity(ephem_enc.len() + recip_enc.len());
    salt.extend_from_slice(ephem_enc.as_bytes());
    salt.extend_from_slice(recip_enc.as_bytes());

    // HKDF-SHA512 → 32-byte wrapping key
    let hkdf = Hkdf::<Sha512>::new(Some(&salt), shared.raw_secret_bytes());
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(HKDF_INFO, wrap_key.as_mut())
        .expect("HKDF expand with 32-byte output never fails");

    // Encrypt the file key; nonce is all-zeros (safe: wrap key is unique per message)
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*wrap_key));
    let nonce = Nonce::from([0u8; 12]);
    let encrypted_file_key = cipher
        .encrypt(&nonce, file_key.as_ref())
        .expect("ChaCha20-Poly1305 encrypt cannot fail");

    WrappedKey {
        ephemeral_pub,
        encrypted_file_key,
    }
}

/// Recover the file key from a `WrappedKey` using the recipient's secret key.
pub fn unwrap_file_key(
    wrapped: &WrappedKey,
    secret_key: &SecretKey,
) -> Result<[u8; FILE_KEY_LEN], Error> {
    // Static ECDH: shared = ECDH(recipient_priv, ephemeral_pub)
    let shared = elliptic_curve::ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        wrapped.ephemeral_pub.as_affine(),
    );

    // Reproduce the HKDF salt
    let ephem_enc = wrapped.ephemeral_pub.to_encoded_point(true);
    let recip_enc = secret_key.public_key().to_encoded_point(true);
    let mut salt = Vec::with_capacity(ephem_enc.len() + recip_enc.len());
    salt.extend_from_slice(ephem_enc.as_bytes());
    salt.extend_from_slice(recip_enc.as_bytes());

    let hkdf = Hkdf::<Sha512>::new(Some(&salt), shared.raw_secret_bytes());
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(HKDF_INFO, wrap_key.as_mut())
        .expect("HKDF expand with 32-byte output never fails");

    // Decrypt the file key
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*wrap_key));
    let nonce = Nonce::from([0u8; 12]);
    let file_key_bytes = cipher
        .decrypt(&nonce, wrapped.encrypted_file_key.as_ref())
        .map_err(|_| Error::Decryption("file key decryption failed (wrong key?)".into()))?;

    if file_key_bytes.len() != FILE_KEY_LEN {
        return Err(Error::Decryption("unexpected file key length".into()));
    }
    let mut out = [0u8; FILE_KEY_LEN];
    out.copy_from_slice(&file_key_bytes);
    Ok(out)
}

/// Encrypt `plaintext` using the STREAM construction (64 KiB chunks).
///
/// Output layout:
/// ```text
/// base_nonce(12)
/// || encrypted_chunk_0
/// || encrypted_chunk_1
/// || ...
/// || encrypted_chunk_n          ← final chunk, tagged with is_final flag
/// ```
/// Each non-final chunk is `CHUNK_SIZE + 16` bytes; the final chunk is
/// `plaintext_remainder + 16` bytes (minimum 16 for an empty message).
pub fn encrypt_payload(file_key: &[u8; FILE_KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(file_key));

    let mut base_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut base_nonce);

    // Upper bound on output size.
    let n_chunks = plaintext.len().div_ceil(CHUNK_SIZE).max(1);
    let mut out = Vec::with_capacity(12 + n_chunks * (CHUNK_SIZE + 16));
    out.extend_from_slice(&base_nonce);

    if plaintext.is_empty() {
        // One empty final chunk so the receiver can verify integrity.
        let nonce = chunk_nonce(&base_nonce, 0, true);
        let ct = cipher
            .encrypt(&nonce, &[][..])
            .expect("ChaCha20-Poly1305 encrypt cannot fail");
        out.extend_from_slice(&ct);
        return out;
    }

    let mut counter: u32 = 0;
    let mut pos = 0;
    while pos < plaintext.len() {
        let end = (pos + CHUNK_SIZE).min(plaintext.len());
        let is_final = end == plaintext.len();
        let nonce = chunk_nonce(&base_nonce, counter, is_final);
        let ct = cipher
            .encrypt(&nonce, &plaintext[pos..end])
            .expect("ChaCha20-Poly1305 encrypt cannot fail");
        out.extend_from_slice(&ct);
        pos = end;
        counter = counter.checked_add(1).expect("chunk counter overflow (>256 TiB input)");
    }

    out
}

/// Decrypt a STREAM payload produced by `encrypt_payload`.
pub fn decrypt_payload(
    file_key: &[u8; FILE_KEY_LEN],
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    // Minimum: 12-byte base nonce + 16-byte AEAD tag for an empty final chunk.
    if data.len() < 12 + 16 {
        return Err(Error::Decryption("ciphertext too short".into()));
    }

    let base_nonce: [u8; 12] = data[..12].try_into().unwrap();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(file_key));

    let mut pos = 12usize;
    let mut counter: u32 = 0;
    let mut plaintext = Vec::new();

    loop {
        let remaining = data.len() - pos;
        if remaining == 0 {
            return Err(Error::Decryption(
                "STREAM: no final chunk found (truncated ciphertext)".into(),
            ));
        }
        let is_final = remaining <= CHUNK_SIZE + 16;
        let chunk_len = if is_final { remaining } else { CHUNK_SIZE + 16 };

        let nonce = chunk_nonce(&base_nonce, counter, is_final);
        let pt = cipher
            .decrypt(&nonce, &data[pos..pos + chunk_len])
            .map_err(|_| {
                Error::Decryption(if is_final {
                    "STREAM: final chunk authentication failed".into()
                } else {
                    format!("STREAM: chunk {} authentication failed", counter)
                })
            })?;

        plaintext.extend_from_slice(&pt);
        pos += chunk_len;

        if is_final {
            break;
        }
        counter = counter.checked_add(1).expect("chunk counter overflow");
    }

    Ok(plaintext)
}
