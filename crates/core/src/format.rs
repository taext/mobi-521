use base64ct::{Base64, Encoding};
use std::io::Write;

use crate::{
    crypto::WrappedKey,
    keys::encode_public_key,
    Error,
};

pub const MAGIC: &str = "age-encryption.org/age-512-v2";

/// Serialised representation of an encrypted file.
pub struct EncryptedFile {
    /// bech32m-encoded ephemeral public key
    pub ephemeral_pub_encoded: String,
    /// Encrypted file key bytes (32 plaintext + 16 tag = 48 bytes)
    pub enc_file_key: Vec<u8>,
    /// Raw payload: nonce(12) || ciphertext
    pub payload: Vec<u8>,
}

/// Write the age-512 format to `writer`.
///
/// Format:
/// ```text
/// age-encryption.org/age-512-v1\r\n
/// -> p521 <bech32-ephemeral-pubkey>\r\n
/// <base64(enc_file_key)>\r\n
/// ---\r\n
/// <binary payload>
/// ```
pub fn write_encrypted<W: Write>(
    writer: &mut W,
    wrapped: &WrappedKey,
    payload: &[u8],
) -> Result<(), Error> {
    let ephem_encoded = encode_public_key(&wrapped.ephemeral_pub);
    let enc_fk_b64 = Base64::encode_string(&wrapped.encrypted_file_key);

    writer
        .write_all(
            format!(
                "{}\n-> p521 {}\n{}\n---\n",
                MAGIC, ephem_encoded, enc_fk_b64
            )
            .as_bytes(),
        )
        .map_err(|e| Error::Format(e.to_string()))?;

    writer
        .write_all(payload)
        .map_err(|e| Error::Format(e.to_string()))?;

    Ok(())
}

/// Parse an age-512 encrypted blob.
pub fn parse_encrypted(data: &[u8]) -> Result<EncryptedFile, Error> {
    // The separator between the text header and the binary payload.
    // We look for the line "---" followed by a newline.
    let separator = b"\n---\n";
    let sep_pos = data
        .windows(separator.len())
        .position(|w| w == separator)
        .ok_or_else(|| Error::Format("missing '---' separator".into()))?;

    let header_bytes = &data[..sep_pos];
    let payload = data[sep_pos + separator.len()..].to_vec();

    let header = std::str::from_utf8(header_bytes)
        .map_err(|_| Error::Format("non-UTF-8 characters in header".into()))?;

    let lines: Vec<&str> = header.lines().collect();

    if lines.len() < 3 {
        return Err(Error::Format(format!(
            "header too short: {} lines",
            lines.len()
        )));
    }

    if lines[0] != MAGIC {
        return Err(Error::Format(format!(
            "bad magic: expected '{}', got '{}'",
            MAGIC, lines[0]
        )));
    }

    let recipient_line = lines[1];
    let prefix = "-> p521 ";
    if !recipient_line.starts_with(prefix) {
        return Err(Error::Format(format!(
            "expected '-> p521 <key>', got '{}'",
            recipient_line
        )));
    }
    let ephemeral_pub_encoded = recipient_line[prefix.len()..].trim().to_string();

    let enc_file_key = Base64::decode_vec(lines[2].trim())
        .map_err(|e| Error::Format(format!("bad base64 for encrypted file key: {}", e)))?;

    Ok(EncryptedFile {
        ephemeral_pub_encoded,
        enc_file_key,
        payload,
    })
}
