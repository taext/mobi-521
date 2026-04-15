#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz key decoding with arbitrary bytes interpreted as UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        // Try decoding as public key
        let _ = mobi521_core::keys::decode_public_key(s);
        // Try decoding as secret key
        let _ = mobi521_core::keys::decode_secret_key(s);
    }
});
