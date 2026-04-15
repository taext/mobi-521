#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the encrypted file format parser
    // This is the most complex parsing code - good target for finding edge cases
    let _ = mobi521_core::format::parse_encrypted(data);
});
