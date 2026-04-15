"""Tests for mobi521_ext pythonic wrapper."""

import os
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

import mobi521
from mobi521_ext import (
    EncryptedPath,
    EncryptedFile,
    open as eopen,
    encrypt_to,
    decrypt_from,
    load_default_pubkey,
    load_default_privkey,
    load_identity,
    _get_config_dir,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def keypair():
    """Generate a fresh keypair for testing."""
    return mobi521.keygen()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def temp_config(temp_dir, keypair, monkeypatch):
    """Set up a temporary config directory with default keys."""
    config_dir = temp_dir / "config" / "mobi521"
    config_dir.mkdir(parents=True)

    # Write default recipient (public key)
    (config_dir / "default-recipient").write_text(keypair.public_key)

    # Write default identity (private key)
    (config_dir / "default-identity").write_text(keypair.private_key)

    # Set XDG_CONFIG_HOME to use our temp config
    monkeypatch.setenv("XDG_CONFIG_HOME", str(temp_dir / "config"))

    # Clear any env var overrides
    monkeypatch.delenv("MOBI521_PUBKEY", raising=False)
    monkeypatch.delenv("MOBI521_PRIVKEY", raising=False)

    return config_dir


# =============================================================================
# Key Discovery Tests
# =============================================================================

class TestKeyDiscovery:
    """Tests for key loading functions."""

    def test_load_pubkey_from_env(self, monkeypatch):
        """MOBI521_PUBKEY env var should take priority."""
        monkeypatch.setenv("MOBI521_PUBKEY", "mobi5211qtest_from_env")
        assert load_default_pubkey() == "mobi5211qtest_from_env"

    def test_load_pubkey_from_config(self, temp_config, keypair):
        """Should load from config file when env var not set."""
        pubkey = load_default_pubkey()
        assert pubkey == keypair.public_key

    def test_load_pubkey_missing_raises(self, temp_dir, monkeypatch):
        """Should raise FileNotFoundError if no config exists."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(temp_dir / "empty"))
        monkeypatch.delenv("MOBI521_PUBKEY", raising=False)

        with pytest.raises(FileNotFoundError, match="No default public key"):
            load_default_pubkey()

    def test_load_pubkey_empty_raises(self, temp_config):
        """Should raise ValueError if config file is empty."""
        (temp_config / "default-recipient").write_text("   \n")

        with pytest.raises(ValueError, match="empty"):
            load_default_pubkey()

    def test_load_privkey_from_env(self, monkeypatch):
        """MOBI521_PRIVKEY env var should take priority."""
        monkeypatch.setenv("MOBI521_PRIVKEY", "MOBI521-SECRET-KEY1test")
        assert load_default_privkey() == "MOBI521-SECRET-KEY1test"

    def test_load_privkey_from_config(self, temp_config, keypair):
        """Should load from config file when env var not set."""
        privkey = load_default_privkey()
        assert privkey == keypair.private_key

    def test_load_identity(self, temp_config, keypair):
        """Should load named identity from identities/ subdirectory."""
        identities_dir = temp_config / "identities"
        identities_dir.mkdir()
        (identities_dir / "work").write_text(keypair.private_key)

        loaded = load_identity("work")
        assert loaded == keypair.private_key

    def test_load_identity_missing_raises(self, temp_config):
        """Should raise FileNotFoundError for unknown identity."""
        with pytest.raises(FileNotFoundError, match="Identity not found"):
            load_identity("nonexistent")


# =============================================================================
# EncryptedPath Tests
# =============================================================================

class TestEncryptedPath:
    """Tests for EncryptedPath pathlib-style API."""

    def test_write_read_bytes(self, temp_dir, keypair):
        """write_bytes/read_bytes roundtrip should work."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
            privkey=keypair.private_key,
        )

        original = b"Hello, mobi521!"
        path.write_bytes(original)

        assert path.exists()
        assert path.read_bytes() == original

    def test_write_read_text(self, temp_dir, keypair):
        """write_text/read_text roundtrip should work."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
            privkey=keypair.private_key,
        )

        original = "Hej verden! 你好世界!"
        path.write_text(original)

        assert path.read_text() == original

    def test_uses_default_keys(self, temp_dir, temp_config, keypair):
        """Should use default keys from config when not specified."""
        path = EncryptedPath(temp_dir / "test.m521")

        path.write_text("secret")
        assert path.read_text() == "secret"

    def test_exists(self, temp_dir, keypair):
        """exists() should reflect file state."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
        )

        assert not path.exists()
        path.write_bytes(b"test")
        assert path.exists()

    def test_unlink(self, temp_dir, keypair):
        """unlink() should delete the file."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
        )

        path.write_bytes(b"test")
        assert path.exists()

        path.unlink()
        assert not path.exists()

    def test_path_properties(self, temp_dir):
        """name, stem, suffix properties should work."""
        path = EncryptedPath(temp_dir / "myfile.m521")

        assert path.name == "myfile.m521"
        assert path.stem == "myfile"
        assert path.suffix == ".m521"

    def test_with_suffix(self, temp_dir, keypair):
        """with_suffix() should return new EncryptedPath."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
        )

        backup = path.with_suffix(".m521.bak")
        assert backup.suffix == ".bak"
        assert backup._pubkey == keypair.public_key

    def test_fspath(self, temp_dir):
        """Should support os.fspath()."""
        path = EncryptedPath(temp_dir / "test.m521")
        assert os.fspath(path) == str(temp_dir / "test.m521")

    def test_repr(self, temp_dir):
        """repr() should be informative."""
        path = EncryptedPath(temp_dir / "test.m521")
        assert "test.m521" in repr(path)
        assert "EncryptedPath" in repr(path)


# =============================================================================
# Context Manager Tests
# =============================================================================

class TestEncryptedFile:
    """Tests for EncryptedFile context manager."""

    def test_write_mode(self, temp_dir, keypair):
        """Writing via context manager should encrypt on exit."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
            privkey=keypair.private_key,
        )

        with path.open("w") as f:
            f.write("secret text")

        assert path.exists()
        assert path.read_text() == "secret text"

    def test_read_mode(self, temp_dir, keypair):
        """Reading via context manager should decrypt."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
            privkey=keypair.private_key,
        )

        path.write_text("hemmelighed")

        with path.open("r") as f:
            content = f.read()

        assert content == "hemmelighed"

    def test_binary_write(self, temp_dir, keypair):
        """Binary write mode should work."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
            privkey=keypair.private_key,
        )

        with path.open("wb") as f:
            f.write(b"\x00\x01\x02\xff")

        assert path.read_bytes() == b"\x00\x01\x02\xff"

    def test_binary_read(self, temp_dir, keypair):
        """Binary read mode should work."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
            privkey=keypair.private_key,
        )

        path.write_bytes(b"\xde\xad\xbe\xef")

        with path.open("rb") as f:
            data = f.read()

        assert data == b"\xde\xad\xbe\xef"

    def test_read_in_write_mode_raises(self, temp_dir, keypair):
        """read() in write mode should raise IOError."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
        )

        with path.open("w") as f:
            with pytest.raises(IOError, match="Cannot read"):
                f.read()

    def test_write_in_read_mode_raises(self, temp_dir, keypair):
        """write() in read mode should raise IOError."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
            privkey=keypair.private_key,
        )
        path.write_bytes(b"test")

        with path.open("r") as f:
            with pytest.raises(IOError, match="Cannot write"):
                f.write("test")

    def test_type_check_binary_mode(self, temp_dir, keypair):
        """Binary mode should reject str input."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
        )

        with path.open("wb") as f:
            with pytest.raises(TypeError, match="Expected bytes"):
                f.write("string not allowed")

    def test_type_check_text_mode(self, temp_dir, keypair):
        """Text mode should reject bytes input."""
        path = EncryptedPath(
            temp_dir / "test.m521",
            pubkey=keypair.public_key,
        )

        with path.open("w") as f:
            with pytest.raises(TypeError, match="Expected str"):
                f.write(b"bytes not allowed")


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for open(), encrypt_to(), decrypt_from()."""

    def test_eopen_write_read(self, temp_dir, keypair):
        """eopen() should work like built-in open()."""
        filepath = temp_dir / "test.m521"

        with eopen(filepath, "w", pubkey=keypair.public_key) as f:
            f.write("hej")

        with eopen(filepath, "r", privkey=keypair.private_key) as f:
            assert f.read() == "hej"

    def test_encrypt_to_text(self, temp_dir, keypair):
        """encrypt_to() should handle text input."""
        filepath = temp_dir / "test.m521"

        encrypt_to(filepath, "hello", pubkey=keypair.public_key)

        decrypted = mobi521.decrypt(
            keypair.private_key,
            filepath.read_bytes(),
        )
        assert decrypted == b"hello"

    def test_encrypt_to_bytes(self, temp_dir, keypair):
        """encrypt_to() should handle bytes input."""
        filepath = temp_dir / "test.m521"

        encrypt_to(filepath, b"\x00\x01", pubkey=keypair.public_key)

        decrypted = mobi521.decrypt(
            keypair.private_key,
            filepath.read_bytes(),
        )
        assert decrypted == b"\x00\x01"

    def test_decrypt_from_text(self, temp_dir, keypair):
        """decrypt_from() should return text by default."""
        filepath = temp_dir / "test.m521"

        ciphertext = mobi521.encrypt(keypair.public_key, b"secret")
        filepath.write_bytes(ciphertext)

        content = decrypt_from(filepath, privkey=keypair.private_key)
        assert content == "secret"
        assert isinstance(content, str)

    def test_decrypt_from_binary(self, temp_dir, keypair):
        """decrypt_from(binary=True) should return bytes."""
        filepath = temp_dir / "test.m521"

        ciphertext = mobi521.encrypt(keypair.public_key, b"\xff\xfe")
        filepath.write_bytes(ciphertext)

        content = decrypt_from(filepath, privkey=keypair.private_key, binary=True)
        assert content == b"\xff\xfe"
        assert isinstance(content, bytes)

    def test_uses_default_keys(self, temp_dir, temp_config):
        """Convenience functions should use default keys."""
        filepath = temp_dir / "test.m521"

        encrypt_to(filepath, "auto key")
        content = decrypt_from(filepath)

        assert content == "auto key"
