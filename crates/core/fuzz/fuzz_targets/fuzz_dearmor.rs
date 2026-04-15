#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the dearmor function with arbitrary input
    // Should never panic, only return Ok or Err
    let _ = mobi521_core::armor::dearmor(data);
});
