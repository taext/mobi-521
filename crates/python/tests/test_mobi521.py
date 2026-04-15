"""Tests for mobi521 Python bindings."""

import pytest
import mobi521


# ============================================================================
# Keygen tests
# ============================================================================

def test_keygen_returns_keypair():
    """keygen() should return a Mobi521KeyPair with public and private keys."""
    kp = mobi521.keygen()

    assert hasattr(kp, 'public_key')
    assert hasattr(kp, 'private_key')
    assert kp.public_key.startswith('mobi5211')
    assert kp.private_key.startswith('MOBI521-SECRET-KEY1')


def test_keygen_generates_unique_keys():
    """Each keygen() call should produce different keys."""
    kp1 = mobi521.keygen()
    kp2 = mobi521.keygen()

    assert kp1.public_key != kp2.public_key
    assert kp1.private_key != kp2.private_key


def test_keypair_repr_redacts_private_key():
    """KeyPair repr should not expose the full private key."""
    kp = mobi521.keygen()
    repr_str = repr(kp)

    assert 'REDACTED' in repr_str
    assert kp.private_key not in repr_str


# ============================================================================
# Encrypt/Decrypt tests
# ============================================================================

def test_encrypt_decrypt_roundtrip():
    """Encrypting and decrypting should return the original plaintext."""
    kp = mobi521.keygen()
    plaintext = b"Hello, Python mobi-521!"

    ciphertext = mobi521.encrypt(kp.public_key, plaintext)
    decrypted = mobi521.decrypt(kp.private_key, ciphertext)

    assert decrypted == plaintext


def test_encrypt_decrypt_empty():
    """Empty plaintext should encrypt and decrypt correctly."""
    kp = mobi521.keygen()
    plaintext = b""

    ciphertext = mobi521.encrypt(kp.public_key, plaintext)
    decrypted = mobi521.decrypt(kp.private_key, ciphertext)

    assert decrypted == plaintext


def test_encrypt_decrypt_binary():
    """Binary data (all byte values) should encrypt and decrypt correctly."""
    kp = mobi521.keygen()
    plaintext = bytes(range(256))

    ciphertext = mobi521.encrypt(kp.public_key, plaintext)
    decrypted = mobi521.decrypt(kp.private_key, ciphertext)

    assert decrypted == plaintext


def test_encrypt_decrypt_large():
    """Large plaintext (1MB) should encrypt and decrypt correctly."""
    kp = mobi521.keygen()
    plaintext = b"A" * (1024 * 1024)  # 1MB

    ciphertext = mobi521.encrypt(kp.public_key, plaintext)
    decrypted = mobi521.decrypt(kp.private_key, ciphertext)

    assert decrypted == plaintext


def test_decrypt_fails_with_wrong_key():
    """Decrypting with wrong key should raise ValueError."""
    kp1 = mobi521.keygen()
    kp2 = mobi521.keygen()
    plaintext = b"secret"

    ciphertext = mobi521.encrypt(kp1.public_key, plaintext)

    with pytest.raises(ValueError):
        mobi521.decrypt(kp2.private_key, ciphertext)


def test_encrypt_fails_with_invalid_key():
    """Encrypting with invalid public key should raise ValueError."""
    with pytest.raises(ValueError):
        mobi521.encrypt("invalid-key", b"test")


def test_decrypt_fails_with_invalid_ciphertext():
    """Decrypting invalid ciphertext should raise ValueError."""
    kp = mobi521.keygen()

    with pytest.raises(ValueError):
        mobi521.decrypt(kp.private_key, b"not valid ciphertext")


# ============================================================================
# Sign/Verify tests
# ============================================================================

def test_sign_verify_roundtrip():
    """Signing and verifying should work correctly."""
    kp = mobi521.keygen()
    message = b"Message to sign"

    signature = mobi521.sign(kp.private_key, message)

    # Signature should be base64-encoded, ~176 chars for P-521
    assert len(signature) >= 170

    # Verify should return True
    result = mobi521.verify(kp.public_key, message, signature)
    assert result is True


def test_verify_fails_on_tampered_message():
    """Verifying with tampered message should raise ValueError."""
    kp = mobi521.keygen()
    message = b"Original message"

    signature = mobi521.sign(kp.private_key, message)

    with pytest.raises(ValueError):
        mobi521.verify(kp.public_key, b"Tampered message", signature)


def test_verify_fails_with_wrong_key():
    """Verifying with wrong public key should raise ValueError."""
    kp1 = mobi521.keygen()
    kp2 = mobi521.keygen()
    message = b"Test message"

    signature = mobi521.sign(kp1.private_key, message)

    with pytest.raises(ValueError):
        mobi521.verify(kp2.public_key, message, signature)


def test_sign_fails_with_invalid_key():
    """Signing with invalid key should raise ValueError."""
    with pytest.raises(ValueError):
        mobi521.sign("invalid-key", b"test")


def test_verify_fails_with_invalid_signature():
    """Verifying with invalid signature should raise ValueError."""
    kp = mobi521.keygen()

    with pytest.raises(ValueError):
        mobi521.verify(kp.public_key, b"test", "not-valid-base64!!!")


# ============================================================================
# Armor/Dearmor tests
# ============================================================================

def test_armor_produces_pem_format():
    """armor() should produce PEM-like format with header and footer."""
    data = b"test data"
    armored = mobi521.armor(data)

    assert "-----BEGIN MOBI-521 ENCRYPTED FILE-----" in armored
    assert "-----END MOBI-521 ENCRYPTED FILE-----" in armored


def test_armor_dearmor_roundtrip():
    """Armoring and dearmoring should return the original data."""
    data = b"test binary data \x00\x01\x02"

    armored = mobi521.armor(data)
    dearmored = mobi521.dearmor(armored)

    assert dearmored == data


def test_dearmor_fails_on_invalid_input():
    """dearmor() should raise ValueError on invalid input."""
    with pytest.raises(ValueError):
        mobi521.dearmor("not valid armor")


def test_decrypt_accepts_armored_ciphertext():
    """decrypt() should automatically handle armored ciphertext."""
    kp = mobi521.keygen()
    plaintext = b"test message"

    # encrypt() returns raw bytes, armor it
    raw_ciphertext = mobi521.encrypt(kp.public_key, plaintext)

    # decrypt should work with raw ciphertext
    decrypted = mobi521.decrypt(kp.private_key, raw_ciphertext)
    assert decrypted == plaintext
