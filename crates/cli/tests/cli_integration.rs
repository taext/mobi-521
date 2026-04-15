//! Integration tests for the mobi521 CLI
//!
//! These tests run the actual binary and verify its behavior.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Get a Command for the mobi521 binary
fn mobi521() -> Command {
    Command::cargo_bin("mobi521").unwrap()
}

/// Parse public and secret keys from an identity file
fn parse_identity_file(content: &str) -> (String, String) {
    let public_key = content
        .lines()
        .find(|l| l.starts_with("# public key: "))
        .expect("No public key line found")
        .strip_prefix("# public key: ")
        .unwrap()
        .to_string();

    // Secret key format is MOBI521-SECRET-KEY1... (bech32 uses '1' as separator)
    let secret_key = content
        .lines()
        .find(|l| l.starts_with("MOBI521-SECRET-KEY1"))
        .expect("No secret key line found")
        .to_string();

    (public_key, secret_key)
}

// ============================================================================
// Keygen tests
// ============================================================================

#[test]
fn keygen_outputs_keypair_to_stdout() {
    mobi521()
        .arg("keygen")
        .assert()
        .success()
        .stdout(predicate::str::contains("# public key: mobi5211"))
        .stdout(predicate::str::contains("MOBI521-SECRET-KEY1"));
}

#[test]
fn keygen_with_output_file_creates_identity_file() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");

    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success()
        .stderr(predicate::str::contains("Public key:"))
        .stderr(predicate::str::contains("Identity written to:"));

    // Verify file was created and contains expected content
    let content = fs::read_to_string(&identity_path).unwrap();
    assert!(content.contains("# mobi-521 identity file"), "Missing header");
    assert!(content.contains("# public key: mobi5211"), "Missing public key");
    assert!(content.contains("MOBI521-SECRET-KEY1"), "Missing secret key");
}

#[test]
fn keygen_increments_filename_if_exists() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("key.identity");

    // Create first key
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    assert!(identity_path.exists());

    // Create second key - should get _1 suffix
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success()
        .stderr(predicate::str::contains("original existed"));

    let incremented_path = tmp.path().join("key_1.identity");
    assert!(incremented_path.exists());
}

#[test]
fn keygen_with_qr_shows_qr_codes() {
    mobi521()
        .arg("keygen")
        .arg("--qr")
        .assert()
        .success()
        .stderr(predicate::str::contains("Public Key QR Code:"))
        .stderr(predicate::str::contains("Private Key QR Code"));
}

// ============================================================================
// Encrypt/Decrypt roundtrip tests
// ============================================================================

#[test]
fn encrypt_decrypt_roundtrip_with_message_flag() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    // Extract keys from identity file
    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Encrypt a message
    let ciphertext_path = tmp.path().join("encrypted.m521");
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg("Hello, mobi-521!")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Verify ciphertext file exists and is armored
    let ciphertext = fs::read_to_string(&ciphertext_path).unwrap();
    assert!(ciphertext.contains("-----BEGIN MOBI-521 ENCRYPTED FILE-----"));
    assert!(ciphertext.contains("-----END MOBI-521 ENCRYPTED FILE-----"));

    // Decrypt the message
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg(&ciphertext_path)
        .assert()
        .success()
        .stdout("Hello, mobi-521!");
}

#[test]
fn encrypt_decrypt_roundtrip_with_file_input() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let plaintext_path = tmp.path().join("plaintext.txt");
    let ciphertext_path = tmp.path().join("encrypted.m521");
    let decrypted_path = tmp.path().join("decrypted.txt");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    // Extract public key
    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Create plaintext file
    let original_content = "This is a test file.\nWith multiple lines.\n";
    fs::write(&plaintext_path, original_content).unwrap();

    // Encrypt file
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-o")
        .arg(&ciphertext_path)
        .arg(&plaintext_path)
        .assert()
        .success();

    // Decrypt to file
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg("-o")
        .arg(&decrypted_path)
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Verify content matches
    let decrypted_content = fs::read_to_string(&decrypted_path).unwrap();
    assert_eq!(decrypted_content, original_content);
}

#[test]
fn encrypt_decrypt_roundtrip_binary_data() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let binary_path = tmp.path().join("binary.bin");
    let ciphertext_path = tmp.path().join("encrypted.m521");
    let decrypted_path = tmp.path().join("decrypted.bin");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Create binary file with all byte values
    let binary_data: Vec<u8> = (0..=255).collect();
    fs::write(&binary_path, &binary_data).unwrap();

    // Encrypt
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-o")
        .arg(&ciphertext_path)
        .arg(&binary_path)
        .assert()
        .success();

    // Decrypt
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg("-o")
        .arg(&decrypted_path)
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Verify binary content matches exactly
    let decrypted_data = fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted_data, binary_data);
}

#[test]
fn encrypt_with_no_armor_produces_raw_binary() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let ciphertext_path = tmp.path().join("encrypted.m521");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Encrypt with --no-armor
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg("test")
        .arg("--no-armor")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Verify it's raw binary (starts with magic string, not armor header)
    let ciphertext = fs::read(&ciphertext_path).unwrap();
    assert!(ciphertext.starts_with(b"m521.app/encrypted/v3"));
}

#[test]
fn decrypt_accepts_both_armored_and_raw() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let armored_path = tmp.path().join("armored.m521");
    let raw_path = tmp.path().join("raw.m521");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    let message = "Test message for both formats";

    // Encrypt armored
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg(message)
        .arg("-o")
        .arg(&armored_path)
        .assert()
        .success();

    // Encrypt raw
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg(message)
        .arg("--no-armor")
        .arg("-o")
        .arg(&raw_path)
        .assert()
        .success();

    // Decrypt armored
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg(&armored_path)
        .assert()
        .success()
        .stdout(message);

    // Decrypt raw
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg(&raw_path)
        .assert()
        .success()
        .stdout(message);
}

#[test]
fn encrypt_decrypt_empty_plaintext() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let ciphertext_path = tmp.path().join("encrypted.m521");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Encrypt empty message
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg("")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Decrypt - should produce empty output
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg(&ciphertext_path)
        .assert()
        .success()
        .stdout("");
}

#[test]
fn encrypt_decrypt_large_plaintext() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let plaintext_path = tmp.path().join("large.txt");
    let ciphertext_path = tmp.path().join("encrypted.m521");
    let decrypted_path = tmp.path().join("decrypted.txt");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Create 1MB plaintext file
    let large_content: String = "A".repeat(1024 * 1024);
    fs::write(&plaintext_path, &large_content).unwrap();

    // Encrypt
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-o")
        .arg(&ciphertext_path)
        .arg(&plaintext_path)
        .assert()
        .success();

    // Decrypt
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg("-o")
        .arg(&decrypted_path)
        .arg(&ciphertext_path)
        .assert()
        .success();

    let decrypted = fs::read_to_string(&decrypted_path).unwrap();
    assert_eq!(decrypted, large_content);
}

// ============================================================================
// Sign/Verify tests
// ============================================================================

#[test]
fn sign_verify_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let message_path = tmp.path().join("message.txt");
    let signature_path = tmp.path().join("message.sig");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Create message file
    let message = "This message will be signed.";
    fs::write(&message_path, message).unwrap();

    // Sign the message
    mobi521()
        .arg("sign")
        .arg("-i")
        .arg(&identity_path)
        .arg("-o")
        .arg(&signature_path)
        .arg(&message_path)
        .assert()
        .success();

    // Verify signature is base64
    let signature = fs::read_to_string(&signature_path).unwrap();
    assert!(!signature.is_empty());
    // P-521 signature is 132 bytes = 176 base64 chars (with padding)
    assert!(signature.len() >= 170);

    // Verify the signature
    mobi521()
        .arg("verify")
        .arg("-p")
        .arg(&public_key)
        .arg("-s")
        .arg(&signature_path)
        .arg(&message_path)
        .assert()
        .success()
        .stderr(predicate::str::contains("Signature valid"));
}

#[test]
fn sign_verify_with_inline_signature() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let message_path = tmp.path().join("message.txt");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    let message = "Inline signature test";
    fs::write(&message_path, message).unwrap();

    // Sign and capture signature from stdout
    let output = mobi521()
        .arg("sign")
        .arg("-i")
        .arg(&identity_path)
        .arg(&message_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let signature = String::from_utf8(output).unwrap().trim().to_string();

    // Verify with signature as string (not file)
    mobi521()
        .arg("verify")
        .arg("-p")
        .arg(&public_key)
        .arg("-s")
        .arg(&signature)
        .arg(&message_path)
        .assert()
        .success()
        .stderr(predicate::str::contains("Signature valid"));
}

#[test]
fn verify_fails_on_tampered_message() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let message_path = tmp.path().join("message.txt");
    let tampered_path = tmp.path().join("tampered.txt");
    let signature_path = tmp.path().join("message.sig");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Create and sign original message
    fs::write(&message_path, "Original message").unwrap();
    mobi521()
        .arg("sign")
        .arg("-i")
        .arg(&identity_path)
        .arg("-o")
        .arg(&signature_path)
        .arg(&message_path)
        .assert()
        .success();

    // Create tampered message
    fs::write(&tampered_path, "Tampered message").unwrap();

    // Verify should fail
    mobi521()
        .arg("verify")
        .arg("-p")
        .arg(&public_key)
        .arg("-s")
        .arg(&signature_path)
        .arg(&tampered_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Signature INVALID"));
}

#[test]
fn verify_fails_with_wrong_key() {
    let tmp = TempDir::new().unwrap();
    let identity1_path = tmp.path().join("identity1");
    let identity2_path = tmp.path().join("identity2");
    let message_path = tmp.path().join("message.txt");
    let signature_path = tmp.path().join("message.sig");

    // Generate two different keypairs
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity1_path)
        .assert()
        .success();

    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity2_path)
        .assert()
        .success();

    // Get public key from second identity
    let identity2_content = fs::read_to_string(&identity2_path).unwrap();
    let (public_key2, _) = parse_identity_file(&identity2_content);

    // Sign with first identity
    fs::write(&message_path, "Test message").unwrap();
    mobi521()
        .arg("sign")
        .arg("-i")
        .arg(&identity1_path)
        .arg("-o")
        .arg(&signature_path)
        .arg(&message_path)
        .assert()
        .success();

    // Verify with second identity's public key - should fail
    mobi521()
        .arg("verify")
        .arg("-p")
        .arg(&public_key2)
        .arg("-s")
        .arg(&signature_path)
        .arg(&message_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Signature INVALID"));
}

// ============================================================================
// Error handling tests
// ============================================================================

#[test]
fn encrypt_fails_with_invalid_pubkey() {
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg("invalid-key")
        .arg("-m")
        .arg("test")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn decrypt_fails_with_invalid_identity() {
    let tmp = TempDir::new().unwrap();
    let ciphertext_path = tmp.path().join("dummy.m521");

    // Create a dummy ciphertext file
    fs::write(&ciphertext_path, "not real ciphertext").unwrap();

    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg("invalid-secret-key")
        .arg(&ciphertext_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn decrypt_fails_with_wrong_key() {
    let tmp = TempDir::new().unwrap();
    let identity1_path = tmp.path().join("identity1");
    let identity2_path = tmp.path().join("identity2");
    let ciphertext_path = tmp.path().join("encrypted.m521");

    // Generate two different keypairs
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity1_path)
        .assert()
        .success();

    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity2_path)
        .assert()
        .success();

    // Get public key from first identity
    let identity1_content = fs::read_to_string(&identity1_path).unwrap();
    let (public_key1, _) = parse_identity_file(&identity1_content);

    // Encrypt with first identity's public key
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key1)
        .arg("-m")
        .arg("secret message")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Try to decrypt with second identity - should fail
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity2_path)
        .arg(&ciphertext_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn decrypt_fails_on_corrupted_ciphertext() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let ciphertext_path = tmp.path().join("corrupted.m521");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Create valid ciphertext first
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg("test")
        .arg("--no-armor")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Corrupt the ciphertext by flipping some bytes
    let mut data = fs::read(&ciphertext_path).unwrap();
    if data.len() > 100 {
        data[100] ^= 0xFF;
    }
    fs::write(&ciphertext_path, data).unwrap();

    // Decrypt should fail
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg(&ciphertext_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn encrypt_without_recipient_and_no_default_fails() {
    // Ensure no default recipient is configured
    let tmp = TempDir::new().unwrap();

    mobi521()
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .arg("encrypt")
        .arg("-m")
        .arg("test")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no --recipient given"));
}

#[test]
fn verify_fails_with_invalid_signature() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let message_path = tmp.path().join("message.txt");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    fs::write(&message_path, "Test message").unwrap();

    // Verify with garbage signature
    mobi521()
        .arg("verify")
        .arg("-p")
        .arg(&public_key)
        .arg("-s")
        .arg("not-a-valid-base64-signature!!!")
        .arg(&message_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("INVALID"));
}

// ============================================================================
// Identity resolution tests
// ============================================================================

#[test]
fn decrypt_accepts_raw_key_string() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");
    let ciphertext_path = tmp.path().join("encrypted.m521");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, secret_key) = parse_identity_file(&identity_content);

    // Encrypt
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg("test with raw key")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Decrypt with raw key string instead of file path
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&secret_key)
        .arg(&ciphertext_path)
        .assert()
        .success()
        .stdout("test with raw key");
}

#[test]
fn identity_file_with_comments_is_parsed_correctly() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("commented.identity");
    let ciphertext_path = tmp.path().join("encrypted.m521");

    // Generate keypair to get valid keys
    let output = mobi521()
        .arg("keygen")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let (public_key, secret_key) = parse_identity_file(&stdout);

    // Create identity file with extra comments and blank lines
    let identity_content = format!(
        "# This is a test identity file\n\
         # Created for testing purposes\n\
         \n\
         # The public key is: {}\n\
         \n\
         # The secret key follows:\n\
         {}\n\
         \n\
         # End of file\n",
        public_key, secret_key
    );
    fs::write(&identity_path, identity_content).unwrap();

    // Encrypt
    mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .arg("-m")
        .arg("commented identity test")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Decrypt should work with the commented file
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg(&ciphertext_path)
        .assert()
        .success()
        .stdout("commented identity test");
}

// ============================================================================
// Completions tests
// ============================================================================

#[test]
fn completions_generates_bash_script() {
    mobi521()
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("_mobi521"));
}

#[test]
fn completions_generates_fish_script() {
    mobi521()
        .arg("completions")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -c mobi521"));
}

#[test]
fn completions_generates_zsh_script() {
    mobi521()
        .arg("completions")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef mobi521"));
}

// ============================================================================
// Help and version tests
// ============================================================================

#[test]
fn help_shows_usage() {
    mobi521()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("P-521 ECC encryption"))
        .stdout(predicate::str::contains("keygen"))
        .stdout(predicate::str::contains("encrypt"))
        .stdout(predicate::str::contains("decrypt"));
}

#[test]
fn version_shows_version() {
    mobi521()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.6")); // Matches 0.6.x
}

#[test]
fn no_args_shows_help() {
    mobi521()
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

// ============================================================================
// Default recipient tests
// ============================================================================

#[test]
fn encrypt_uses_default_recipient_from_config() {
    let tmp = TempDir::new().unwrap();
    let config_dir = tmp.path().join("mobi521");
    fs::create_dir_all(&config_dir).unwrap();

    // Generate a keypair
    let output = mobi521()
        .arg("keygen")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let (public_key, secret_key) = parse_identity_file(&stdout);

    // Write public key as default recipient
    fs::write(config_dir.join("default-recipient"), &public_key).unwrap();

    // Encrypt without -r flag (should use default)
    let ciphertext_path = tmp.path().join("encrypted.m521");
    mobi521()
        .env("XDG_CONFIG_HOME", tmp.path())
        .arg("encrypt")
        .arg("-m")
        .arg("using default recipient")
        .arg("-o")
        .arg(&ciphertext_path)
        .assert()
        .success();

    // Decrypt to verify
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&secret_key)
        .arg(&ciphertext_path)
        .assert()
        .success()
        .stdout("using default recipient");
}

// ============================================================================
// Stdin/stdout piping tests
// ============================================================================

#[test]
fn encrypt_decrypt_via_stdin_stdout() {
    let tmp = TempDir::new().unwrap();
    let identity_path = tmp.path().join("test.identity");

    // Generate keypair
    mobi521()
        .arg("keygen")
        .arg("-o")
        .arg(&identity_path)
        .assert()
        .success();

    let identity_content = fs::read_to_string(&identity_path).unwrap();
    let (public_key, _) = parse_identity_file(&identity_content);

    // Encrypt via stdin, get ciphertext from stdout
    let encrypt_output = mobi521()
        .arg("encrypt")
        .arg("-r")
        .arg(&public_key)
        .write_stdin("piped message")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Decrypt via stdin
    mobi521()
        .arg("decrypt")
        .arg("-i")
        .arg(&identity_path)
        .write_stdin(encrypt_output)
        .assert()
        .success()
        .stdout("piped message");
}
