#![no_main]

use libfuzzer_sys::fuzz_target;
use mobi521_core::keys::{KeyPair, encode_secret_key};

// Use a fixed keypair so fuzzer focuses on ciphertext parsing, not key validation
lazy_static::lazy_static! {
    static ref SECRET_KEY: String = {
        let kp = KeyPair::generate();
        encode_secret_key(&kp.secret)
    };
}

fuzz_target!(|data: &[u8]| {
    // Fuzz the decrypt function with arbitrary ciphertext
    // Should never panic, only return Ok or Err
    let _ = mobi521_core::decrypt(&SECRET_KEY, data);
});
