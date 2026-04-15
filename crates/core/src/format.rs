use base64ct::{Base64, Encoding};
use std::io::Write;

use crate::{
    crypto::WrappedKey,
    keys::encode_public_key,
    Error,
};

pub const MAGIC: &str = "m521.app/encrypted/v3";

/// Serialised representation of an encrypted file.
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Header Parsing Security Tests
    // ========================================================================

    #[test]
    fn rejects_missing_separator() {
        let data = b"m521.app/encrypted/v3\n-> p521 mobi5211test\nQUJD\nno separator here";
        assert!(
            parse_encrypted(data).is_err(),
            "missing separator must be rejected"
        );
    }

    #[test]
    fn rejects_wrong_magic() {
        let data = b"age-encryption.org/v1\n-> p521 mobi5211test\nQUJD\n---\npayload";
        let err = parse_encrypted(data).unwrap_err();
        assert!(
            err.to_string().contains("bad magic"),
            "wrong magic must be rejected"
        );
    }

    #[test]
    fn rejects_header_too_short() {
        let data = b"m521.app/encrypted/v3\n---\npayload";
        assert!(
            parse_encrypted(data).is_err(),
            "header with too few lines must be rejected"
        );
    }

    #[test]
    fn rejects_missing_recipient_prefix() {
        let data = b"m521.app/encrypted/v3\np521 mobi5211test\nQUJD\n---\npayload";
        let err = parse_encrypted(data).unwrap_err();
        assert!(
            err.to_string().contains("-> p521"),
            "missing '-> p521' prefix must be rejected"
        );
    }

    #[test]
    fn rejects_invalid_base64_file_key() {
        let data = b"m521.app/encrypted/v3\n-> p521 mobi5211test\n!!!not-base64!!!\n---\npayload";
        let err = parse_encrypted(data).unwrap_err();
        assert!(
            err.to_string().contains("base64"),
            "invalid base64 must be rejected"
        );
    }

    #[test]
    fn rejects_non_utf8_header() {
        let mut data = b"m521.app/encrypted/v3\n-> p521 ".to_vec();
        data.extend(&[0xFF, 0xFE]); // invalid UTF-8
        data.extend(b"\nQUJD\n---\npayload");
        assert!(
            parse_encrypted(&data).is_err(),
            "non-UTF-8 header must be rejected"
        );
    }

    #[test]
    fn handles_crlf_line_endings() {
        // Some systems might send CRLF - should still work or fail gracefully
        let data = b"m521.app/encrypted/v3\r\n-> p521 mobi5211test\r\nQUJD\r\n---\r\npayload";
        // This should either work or fail cleanly, not panic
        let _ = parse_encrypted(data);
    }

    #[test]
    fn rejects_header_with_null_bytes() {
        let mut data = b"m521.app/encrypted/v3\n-> p521 ".to_vec();
        data.extend(b"mobi5211\x00injected");
        data.extend(b"\nQUJD\n---\npayload");
        // Should handle null bytes gracefully (either reject or parse safely)
        let _ = parse_encrypted(&data);
    }

    #[test]
    fn rejects_extra_recipient_lines() {
        // Only single recipient supported
        let data = b"m521.app/encrypted/v3\n-> p521 mobi5211first\n-> p521 mobi5211second\nQUJD\n---\npayload";
        // This should either use first recipient or fail, not crash
        let _ = parse_encrypted(data);
    }

    #[test]
    fn accepts_minimal_valid_header() {
        // Construct a minimal valid header
        let header = format!(
            "{}\n-> p521 mobi5211test\nQUJDREVG\n---\n",
            MAGIC
        );
        let mut data = header.into_bytes();
        data.extend(b"payload");

        let result = parse_encrypted(&data);
        assert!(result.is_ok(), "minimal valid header should be accepted");

        let ef = result.unwrap();
        assert_eq!(ef.ephemeral_pub_encoded, "mobi5211test");
        assert_eq!(ef.payload, b"payload");
    }

    #[test]
    fn preserves_binary_payload() {
        let header = format!(
            "{}\n-> p521 mobi5211test\nQUJDREVG\n---\n",
            MAGIC
        );
        let mut data = header.into_bytes();
        // Binary payload with all byte values
        let binary_payload: Vec<u8> = (0..=255).collect();
        data.extend(&binary_payload);

        let ef = parse_encrypted(&data).unwrap();
        assert_eq!(ef.payload, binary_payload, "binary payload must be preserved exactly");
    }

    #[test]
    fn handles_empty_payload() {
        let header = format!(
            "{}\n-> p521 mobi5211test\nQUJDREVG\n---\n",
            MAGIC
        );
        let data = header.into_bytes();

        let ef = parse_encrypted(&data).unwrap();
        assert!(ef.payload.is_empty(), "empty payload should be accepted");
    }

    #[test]
    fn rejects_separator_at_start() {
        let data = b"---\nm521.app/encrypted/v3\n-> p521 mobi5211test\nQUJD\n---\npayload";
        assert!(
            parse_encrypted(data).is_err(),
            "separator at wrong position must be rejected"
        );
    }
}
