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
