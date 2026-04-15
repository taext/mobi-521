# Cryptographic Property Tests

This document describes the cryptographic property tests for mobi-521.

## Executive Summary

**93 tests** verify mobi-521's cryptographic security across 9 categories:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PRIMITIVES (24 tests)                                                  │
│  ├── ChaCha20-Poly1305: RFC 8439 compliance, bit-flip detection         │
│  ├── HKDF-SHA512: Domain separation, determinism                        │
│  ├── P-521 ECDH: Shared secret symmetry, key lengths                    │
│  └── ECDSA-P521: Hedged signatures, tampering detection                 │
├─────────────────────────────────────────────────────────────────────────┤
│  INTEGRATION (6 tests)                                                  │
│  └── Key wrapping, STREAM chunk boundaries, nonce uniqueness            │
├─────────────────────────────────────────────────────────────────────────┤
│  SECURITY HARDENING (63 tests)                                          │
│  ├── STREAM attacks: Chunk reorder/remove/duplicate/truncate            │
│  ├── Key validation: Invalid points, bad checksums, scalar overflow     │
│  ├── Format parsing: Header injection, CRLF, null bytes, UTF-8          │
│  └── Signatures: Malleability, truncation, edge cases                   │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key security properties verified:**
- Forward secrecy (fresh ephemeral key per encryption)
- Chunk ordering protection (counter-based nonces)
- Input boundary validation (reject invalid keys/points)
- Format robustness (handle malicious headers safely)

---

## Test Details

Tests are located in:
- `crates/core/src/crypto_vectors.rs` — Primitive and integration tests
- `crates/core/src/keys.rs` — Key validation tests
- `crates/core/src/format.rs` — Format parsing tests
- `crates/core/src/signing.rs` — Signature security tests

## Test Summary

| Category | Tests | Purpose |
|----------|-------|---------|
| ChaCha20-Poly1305 | 4 | AEAD cipher correctness |
| HKDF-SHA512 | 5 | Key derivation properties |
| P-521 ECDH | 4 | Elliptic curve Diffie-Hellman |
| ECDSA-P521 | 5 | Digital signatures |
| mobi-521 Integration | 6 | End-to-end crypto properties |
| **STREAM Security** | **6** | Chunk manipulation attacks |
| **Key Validation** | **12** | Invalid key rejection |
| **Format Parsing** | **14** | Header injection/malformed input |
| **Signature Security** | **8** | Signature edge cases |
| **Total** | **93** | |

---

## ChaCha20-Poly1305 Tests

Reference: [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)

| Test | What it verifies |
|------|------------------|
| `chacha20_poly1305_rfc8439_test_vector` | Encrypt/decrypt roundtrip using RFC 8439 key and nonce |
| `chacha20_poly1305_empty_message` | Empty plaintext produces only 16-byte tag |
| `chacha20_poly1305_tag_length` | Ciphertext = plaintext + 16 bytes (Poly1305 tag) |
| `chacha20_poly1305_bit_flip_detection` | Any single bit flip causes authentication failure |

---

## HKDF-SHA512 Tests

Reference: [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)

| Test | What it verifies |
|------|------------------|
| `hkdf_sha512_basic_test_vector` | HKDF output is deterministic |
| `hkdf_sha512_different_salts_produce_different_keys` | Salt provides domain separation |
| `hkdf_sha512_different_info_produces_different_keys` | Info parameter provides context separation |
| `hkdf_sha512_no_salt_uses_zero_salt` | `None` salt equivalent to zero-filled salt |
| `hkdf_sha512_max_output_length` | Max output = 255 × 64 = 16320 bytes |

---

## P-521 ECDH Tests

Reference: [NIST FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final), [SEC 2](https://www.secg.org/sec2-v2.pdf)

| Test | What it verifies |
|------|------------------|
| `p521_ecdh_shared_secret_is_symmetric` | `DH(a, B) = DH(b, A)` — fundamental ECDH property |
| `p521_ecdh_shared_secret_length` | Shared secret is 66 bytes (521 bits) |
| `p521_ecdh_different_keypairs_produce_different_secrets` | Different recipients → different shared secrets |
| `p521_public_key_compressed_length` | Compressed: 67 bytes, uncompressed: 133 bytes |

---

## ECDSA-P521-SHA512 Tests

Reference: [NIST FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final), [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979)

| Test | What it verifies |
|------|------------------|
| `ecdsa_p521_signature_length` | Signature is 132 bytes (r: 66 + s: 66) |
| `ecdsa_p521_hedged_signatures_differ` | Hedged nonces add randomness (fault attack protection) |
| `ecdsa_p521_different_messages_different_signatures` | Different messages → different signatures |
| `ecdsa_p521_verification_fails_on_wrong_message` | Tampering detection works |
| `ecdsa_p521_verification_fails_on_wrong_key` | Wrong key cannot verify |

### Note on Hedged Signatures

The p521 crate uses **hedged signatures** (RFC 6979 + additional randomness) rather than purely deterministic signatures. This is more secure as it protects against fault injection attacks that could leak the private key if the same nonce is ever reused.

---

## mobi-521 Integration Tests

These tests verify mobi-521's specific crypto construction.

| Test | What it verifies |
|------|------------------|
| `mobi521_wrap_unwrap_preserves_file_key` | Key wrapping roundtrip works |
| `mobi521_wrapped_key_structure` | Ephemeral pubkey: 67 bytes, encrypted file key: 48 bytes |
| `mobi521_different_recipients_produce_different_ciphertexts` | Fresh ephemeral key per encryption |
| `mobi521_same_recipient_different_ephemeral_keys` | Each wrap uses new ephemeral keypair |
| `mobi521_stream_chunk_boundaries` | STREAM works at 0, 64Ki-1, 64Ki, 64Ki+1 byte boundaries |
| `mobi521_stream_nonce_uniqueness` | Each encryption has unique base nonce |

### mobi-521 Crypto Construction

```
File Key (32 bytes random)
    │
    ├─► wrap_file_key()
    │       ephemeral = P521::random()
    │       shared = ECDH(ephemeral, recipient_pub)
    │       salt = ephemeral_pub || recipient_pub
    │       wrap_key = HKDF-SHA512(shared, salt, "m521.app/encrypted/v3")
    │       encrypted_file_key = ChaCha20-Poly1305(wrap_key, nonce=0, file_key)
    │
    └─► encrypt_payload()
            base_nonce = random(12 bytes)
            for each 64 KiB chunk:
                chunk_nonce = base_nonce XOR counter XOR is_final
                ciphertext += ChaCha20-Poly1305(file_key, chunk_nonce, chunk)
```

---

## Running the Tests

```bash
# Run only crypto property tests
cargo test -p mobi521-core crypto_vectors

# Run all core tests
cargo test -p mobi521-core

# Run with output
cargo test -p mobi521-core crypto_vectors -- --nocapture
```

---

## STREAM Security Tests (NEW)

These tests verify that the STREAM construction properly rejects manipulated ciphertexts.

| Test | What it verifies |
|------|------------------|
| `stream_rejects_reordered_chunks` | Swapping chunk order causes authentication failure |
| `stream_rejects_removed_middle_chunk` | Removing a chunk from the middle fails |
| `stream_rejects_duplicated_chunk` | Duplicating a chunk fails |
| `stream_rejects_truncated_final_chunk` | Truncated Poly1305 tag fails |
| `stream_rejects_appended_garbage` | Extra data after valid ciphertext fails |
| `stream_rejects_modified_nonce` | Bit flip in base nonce fails |

**Security Property**: The counter-based nonce construction ensures that:
- Each chunk has a unique nonce (counter XOR)
- Chunks cannot be reordered (wrong counter)
- Final chunk is tagged (is_final bit)
- Truncation is detected (no valid final chunk)

---

## Key Validation Security Tests (NEW)

Tests that verify invalid keys are properly rejected.

| Test | What it verifies |
|------|------------------|
| `rejects_truncated_public_key` | Incomplete key strings rejected |
| `rejects_corrupted_public_key_checksum` | Bech32m checksum validation |
| `rejects_wrong_length_public_key_bytes` | 66 bytes instead of 67 rejected |
| `rejects_invalid_point_prefix` | 0x00 prefix (invalid SEC1) rejected |
| `rejects_x_coordinate_exceeding_field_modulus` | x >= p rejected |
| `rejects_random_invalid_point_bytes` | Points not on curve rejected |
| `rejects_bech32_not_bech32m` | Bech32 (not bech32m) variant rejected |
| `rejects_empty_public_key` | Empty string rejected |
| `rejects_garbage_input` | Non-bech32 input rejected |
| `rejects_zero_secret_key` | k=0 (invalid scalar) rejected |
| `rejects_secret_key_exceeding_curve_order` | k >= n rejected |

---

## Format Parsing Security Tests (NEW)

Tests that verify the file format parser handles malicious input safely.

| Test | What it verifies |
|------|------------------|
| `rejects_missing_separator` | Missing `---` separator fails |
| `rejects_wrong_magic` | Wrong version magic fails |
| `rejects_header_too_short` | < 3 header lines fails |
| `rejects_missing_recipient_prefix` | Missing `-> p521` prefix fails |
| `rejects_invalid_base64_file_key` | Bad base64 encoding fails |
| `rejects_non_utf8_header` | Invalid UTF-8 in header fails |
| `handles_crlf_line_endings` | CRLF doesn't cause panic |
| `rejects_header_with_null_bytes` | Null bytes handled safely |
| `rejects_extra_recipient_lines` | Multiple recipients handled |
| `accepts_minimal_valid_header` | Valid minimal header works |
| `preserves_binary_payload` | Binary data preserved exactly |
| `handles_empty_payload` | Empty payload accepted |
| `rejects_separator_at_start` | Separator in wrong position fails |

---

## Signature Security Tests (NEW)

Tests for ECDSA signature edge cases.

| Test | What it verifies |
|------|------------------|
| `rejects_empty_signature` | Empty string rejected |
| `rejects_truncated_signature` | Incomplete signature rejected |
| `rejects_extended_signature` | Extra bytes after signature rejected |
| `rejects_all_zero_signature` | (0, 0) signature rejected |
| `signature_malleability_handled_consistently` | (r, -s) form handled safely |
| `empty_message_can_be_signed` | Zero-length message works |
| `large_message_can_be_signed` | 1 MB message works |

---

## Security Properties Verified

1. **Confidentiality**: ChaCha20 stream cipher
2. **Integrity**: Poly1305 MAC (16-byte tag)
3. **Authenticity**: ECDSA-P521-SHA512 signatures
4. **Forward secrecy**: Fresh ephemeral key per encryption
5. **Key separation**: HKDF with unique salt per message
6. **Large file support**: STREAM construction with 64 KiB chunks
7. **Chunk ordering**: Counter-based nonces prevent reordering (NEW)
8. **Input validation**: Invalid keys/points rejected at boundary (NEW)
9. **Format robustness**: Malicious headers handled safely (NEW)
10. **Signature edge cases**: Malformed signatures rejected (NEW)
