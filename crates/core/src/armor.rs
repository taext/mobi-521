use base64ct::{Base64, Encoding};

use crate::Error;

pub const HEADER: &str = "-----BEGIN MOBI-521 ENCRYPTED FILE-----";
pub const FOOTER: &str = "-----END MOBI-521 ENCRYPTED FILE-----";
const LINE_WIDTH: usize = 64;

/// Wrap raw encrypted bytes in ASCII armor.
pub fn armor(data: &[u8]) -> String {
    let b64 = Base64::encode_string(data);
    let mut out = String::new();
    out.push_str(HEADER);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(LINE_WIDTH) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is always valid UTF-8"));
        out.push('\n');
    }
    out.push_str(FOOTER);
    out.push('\n');
    out
}

/// Decode ASCII-armored data back to raw bytes.
pub fn dearmor(data: &[u8]) -> Result<Vec<u8>, Error> {
    let text = std::str::from_utf8(data)
        .map_err(|_| Error::Format("armor: non-UTF-8 input".into()))?;
    dearmor_str(text)
}

pub fn dearmor_str(text: &str) -> Result<Vec<u8>, Error> {
    let mut lines = text.lines();
    let first = lines
        .next()
        .ok_or_else(|| Error::Format("armor: empty input".into()))?;
    if first.trim() != HEADER {
        return Err(Error::Format(format!(
            "armor: expected '{}', got '{}'",
            HEADER,
            first.trim()
        )));
    }
    let mut b64 = String::new();
    let mut found_footer = false;
    for line in lines {
        let l = line.trim();
        if l == FOOTER {
            found_footer = true;
            break;
        }
        b64.push_str(l);
    }
    if !found_footer {
        return Err(Error::Format(format!("armor: missing '{}'", FOOTER)));
    }
    Base64::decode_vec(&b64)
        .map_err(|e| Error::Format(format!("armor: invalid base64: {}", e)))
}

/// Returns `true` if `data` looks like ASCII-armored mobi-521 output.
pub fn is_armored(data: &[u8]) -> bool {
    data.starts_with(HEADER.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn armor_dearmor_roundtrip() {
        let data = b"hello world this is test data 1234567890";
        let armored = armor(data);
        let recovered = dearmor(armored.as_bytes()).unwrap();
        assert_eq!(data.as_slice(), recovered.as_slice());
    }

    #[test]
    fn armor_dearmor_empty() {
        let armored = armor(b"");
        let recovered = dearmor(armored.as_bytes()).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn armor_dearmor_binary_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let armored = armor(&data);
        let recovered = dearmor(armored.as_bytes()).unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    fn armored_output_has_correct_header_footer() {
        let armored = armor(b"test");
        assert!(armored.starts_with(HEADER));
        assert!(armored.trim_end().ends_with(FOOTER));
    }

    #[test]
    fn is_armored_detects_armored_data() {
        let armored = armor(b"test");
        assert!(is_armored(armored.as_bytes()));
    }

    #[test]
    fn is_armored_rejects_raw_data() {
        assert!(!is_armored(b"raw binary data"));
        assert!(!is_armored(b""));
        assert!(!is_armored(b"age-encryption.org/age-512-v2"));
    }

    #[test]
    fn dearmor_bad_header_returns_error() {
        let bad = b"-----BEGIN SOMETHING ELSE-----\nZGF0YQ==\n-----END SOMETHING ELSE-----\n";
        assert!(dearmor(bad).is_err());
    }

    #[test]
    fn dearmor_missing_footer_returns_error() {
        let bad = format!("{}\nZGF0YQ==\n", HEADER);
        assert!(dearmor(bad.as_bytes()).is_err());
    }

    #[test]
    fn dearmor_empty_input_returns_error() {
        assert!(dearmor(b"").is_err());
    }
}
