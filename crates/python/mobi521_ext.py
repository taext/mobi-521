"""Pythonic wrapper for mobi521 with pathlib-style API and context managers.

Usage:
    from mobi521_ext import EncryptedPath, open as eopen

    # Pathlib-style
    p = EncryptedPath("secrets.m521")
    p.write_text("mine hemmeligheder")
    print(p.read_text())

    # Context manager
    with eopen("diary.m521", "w") as f:
        f.write("dagens tanker...")
"""

from pathlib import Path
from typing import Union, Optional
import os

import mobi521 as _core  # PyO3 binding


# =============================================================================
# Key Discovery
# =============================================================================

def _get_config_dir() -> Path:
    """Get mobi521 config directory (XDG-compliant)."""
    if xdg := os.environ.get("XDG_CONFIG_HOME"):
        return Path(xdg) / "mobi521"
    return Path.home() / ".config" / "mobi521"


def load_default_pubkey() -> str:
    """Load default public key from env var or config file.

    Search order:
    1. MOBI521_PUBKEY environment variable
    2. ~/.config/mobi521/default-recipient (or $XDG_CONFIG_HOME/mobi521/default-recipient)

    Raises:
        FileNotFoundError: If no default key is configured.
        ValueError: If the key file is empty.
    """
    # 1. Environment variable
    if pubkey := os.environ.get("MOBI521_PUBKEY"):
        return pubkey.strip()

    # 2. Config file (same as CLI)
    config_file = _get_config_dir() / "default-recipient"
    if not config_file.exists():
        raise FileNotFoundError(
            f"No default public key found.\n"
            f"Set MOBI521_PUBKEY env var or create {config_file}"
        )

    key = config_file.read_text().strip()
    if not key:
        raise ValueError(f"Default recipient file is empty: {config_file}")

    return key


def load_default_privkey() -> str:
    """Load default private key from env var or config file.

    Search order:
    1. MOBI521_PRIVKEY environment variable
    2. ~/.config/mobi521/default-identity (or $XDG_CONFIG_HOME/mobi521/default-identity)

    Raises:
        FileNotFoundError: If no default key is configured.
        ValueError: If the key file is empty.
    """
    # 1. Environment variable
    if privkey := os.environ.get("MOBI521_PRIVKEY"):
        return privkey.strip()

    # 2. Config file
    config_file = _get_config_dir() / "default-identity"
    if not config_file.exists():
        raise FileNotFoundError(
            f"No default private key found.\n"
            f"Set MOBI521_PRIVKEY env var or create {config_file}"
        )

    key = config_file.read_text().strip()
    if not key:
        raise ValueError(f"Default identity file is empty: {config_file}")

    return key


def load_identity(name: str) -> str:
    """Load a named identity (private key) from config directory.

    Looks for: ~/.config/mobi521/identities/{name}

    Args:
        name: Identity name (e.g., "work", "personal")

    Returns:
        The private key string.
    """
    identity_file = _get_config_dir() / "identities" / name
    if not identity_file.exists():
        raise FileNotFoundError(f"Identity not found: {identity_file}")

    key = identity_file.read_text().strip()
    if not key:
        raise ValueError(f"Identity file is empty: {identity_file}")

    return key


# =============================================================================
# EncryptedPath - Pathlib-style API
# =============================================================================

class EncryptedPath:
    """Pathlib-style API for encrypted files.

    Examples:
        # With explicit keys
        p = EncryptedPath("secret.m521", pubkey="mobi5211q...")
        p.write_text("hemmelighed")

        # With default keys from config
        p = EncryptedPath("diary.m521")
        p.write_text("mine tanker")
        print(p.read_text())

        # Context manager for file-like operations
        with p.open("w") as f:
            f.write("ny tekst")
    """

    def __init__(
        self,
        path: Union[str, Path],
        *,
        pubkey: Optional[str] = None,
        privkey: Optional[str] = None,
    ):
        """Initialize an EncryptedPath.

        Args:
            path: Path to the encrypted file.
            pubkey: Public key for encryption. If None, uses default.
            privkey: Private key for decryption. If None, uses default.
        """
        self.path = Path(path)
        self._pubkey = pubkey
        self._privkey = privkey

    @property
    def pubkey(self) -> str:
        """Get public key, loading default if not set."""
        if self._pubkey is None:
            self._pubkey = load_default_pubkey()
        return self._pubkey

    @property
    def privkey(self) -> str:
        """Get private key, loading default if not set."""
        if self._privkey is None:
            self._privkey = load_default_privkey()
        return self._privkey

    # === Pathlib-style write methods ===

    def write_bytes(self, data: bytes) -> int:
        """Encrypt and write bytes to file.

        Args:
            data: Plaintext bytes to encrypt.

        Returns:
            Number of bytes written (ciphertext size).
        """
        ciphertext = _core.encrypt(self.pubkey, data)
        return self.path.write_bytes(ciphertext)

    def write_text(self, text: str, encoding: str = "utf-8") -> int:
        """Encrypt and write text to file.

        Args:
            text: Plaintext string to encrypt.
            encoding: Text encoding (default: utf-8).

        Returns:
            Number of bytes written (ciphertext size).
        """
        return self.write_bytes(text.encode(encoding))

    # === Pathlib-style read methods ===

    def read_bytes(self) -> bytes:
        """Read and decrypt file contents as bytes.

        Returns:
            Decrypted plaintext bytes.
        """
        ciphertext = self.path.read_bytes()
        return _core.decrypt(self.privkey, ciphertext)

    def read_text(self, encoding: str = "utf-8") -> str:
        """Read and decrypt file contents as text.

        Args:
            encoding: Text encoding (default: utf-8).

        Returns:
            Decrypted plaintext string.
        """
        return self.read_bytes().decode(encoding)

    # === Pathlib-style utility methods ===

    def exists(self) -> bool:
        """Check if the encrypted file exists."""
        return self.path.exists()

    def unlink(self, missing_ok: bool = False) -> None:
        """Delete the encrypted file."""
        self.path.unlink(missing_ok=missing_ok)

    @property
    def name(self) -> str:
        """The final component of the path."""
        return self.path.name

    @property
    def stem(self) -> str:
        """The final component without the .m521 suffix."""
        return self.path.stem

    @property
    def suffix(self) -> str:
        """The file extension."""
        return self.path.suffix

    def with_suffix(self, suffix: str) -> "EncryptedPath":
        """Return a new path with the suffix changed."""
        return EncryptedPath(
            self.path.with_suffix(suffix),
            pubkey=self._pubkey,
            privkey=self._privkey,
        )

    # === Context manager support ===

    def open(self, mode: str = "r") -> "EncryptedFile":
        """Open the encrypted file with a context manager.

        Args:
            mode: "r" for read, "w" for write, "rb"/"wb" for binary.

        Returns:
            An EncryptedFile context manager.

        Example:
            with path.open("w") as f:
                f.write("secret text")
        """
        return EncryptedFile(self, mode)

    def __repr__(self) -> str:
        return f"EncryptedPath({self.path!r})"

    def __str__(self) -> str:
        return str(self.path)

    def __fspath__(self) -> str:
        """Support os.fspath() for compatibility."""
        return str(self.path)


# =============================================================================
# EncryptedFile - Context Manager
# =============================================================================

class EncryptedFile:
    """Context manager for encrypted file I/O.

    Provides file-like read/write operations that encrypt on close.

    Examples:
        # Write mode
        with EncryptedFile(epath, "w") as f:
            f.write("secret text")

        # Read mode
        with EncryptedFile(epath, "r") as f:
            content = f.read()

        # Binary mode
        with EncryptedFile(epath, "wb") as f:
            f.write(b"\\x00\\x01\\x02")
    """

    def __init__(self, epath: EncryptedPath, mode: str = "r"):
        """Initialize an EncryptedFile.

        Args:
            epath: The EncryptedPath to operate on.
            mode: File mode - "r", "w", "rb", "wb".
        """
        self.epath = epath
        self.mode = mode
        self._binary = "b" in mode
        self._writing = "w" in mode
        self._buffer: Union[bytes, str] = b"" if self._binary else ""
        self._closed = False

    def __enter__(self) -> "EncryptedFile":
        """Enter context: load existing content for read mode."""
        if not self._writing and self.epath.exists():
            data = self.epath.read_bytes()
            self._buffer = data if self._binary else data.decode("utf-8")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context: encrypt and write for write mode."""
        if self._writing and exc_type is None:
            data = self._buffer if isinstance(self._buffer, bytes) else self._buffer.encode("utf-8")
            self.epath.write_bytes(data)
        self._closed = True

    def read(self) -> Union[bytes, str]:
        """Read the entire file contents.

        Returns:
            File contents as bytes (binary mode) or str (text mode).
        """
        if self._writing:
            raise IOError("Cannot read in write mode")
        return self._buffer

    def write(self, data: Union[bytes, str]) -> int:
        """Write data to the file buffer.

        Args:
            data: Data to write (bytes or str depending on mode).

        Returns:
            Number of bytes/characters written.
        """
        if not self._writing:
            raise IOError("Cannot write in read mode")
        if self._closed:
            raise IOError("Cannot write to closed file")

        # Type check
        if self._binary and not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data).__name__}")
        if not self._binary and not isinstance(data, str):
            raise TypeError(f"Expected str, got {type(data).__name__}")

        self._buffer = data  # Overwrite (simple implementation)
        return len(data)

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"<EncryptedFile {self.epath.path!r} mode={self.mode!r} {state}>"


# =============================================================================
# Convenience Functions
# =============================================================================

def open(
    path: Union[str, Path],
    mode: str = "r",
    *,
    pubkey: Optional[str] = None,
    privkey: Optional[str] = None,
) -> EncryptedFile:
    """Open an encrypted file (like built-in open()).

    Args:
        path: Path to the encrypted file.
        mode: File mode - "r", "w", "rb", "wb".
        pubkey: Public key for encryption (uses default if None).
        privkey: Private key for decryption (uses default if None).

    Returns:
        An EncryptedFile context manager.

    Example:
        with open("secret.m521", "w") as f:
            f.write("hemmelighed")

        with open("secret.m521", "r") as f:
            print(f.read())
    """
    epath = EncryptedPath(path, pubkey=pubkey, privkey=privkey)
    return epath.open(mode)


def encrypt_to(
    path: Union[str, Path],
    data: Union[bytes, str],
    *,
    pubkey: Optional[str] = None,
) -> int:
    """One-liner to encrypt data to a file.

    Args:
        path: Destination path.
        data: Data to encrypt (bytes or str).
        pubkey: Public key (uses default if None).

    Returns:
        Number of bytes written.

    Example:
        encrypt_to("secret.m521", "mine hemmeligheder")
    """
    epath = EncryptedPath(path, pubkey=pubkey)
    if isinstance(data, str):
        return epath.write_text(data)
    return epath.write_bytes(data)


def decrypt_from(
    path: Union[str, Path],
    *,
    privkey: Optional[str] = None,
    binary: bool = False,
) -> Union[bytes, str]:
    """One-liner to decrypt data from a file.

    Args:
        path: Source path.
        privkey: Private key (uses default if None).
        binary: If True, return bytes instead of str.

    Returns:
        Decrypted content.

    Example:
        content = decrypt_from("secret.m521")
    """
    epath = EncryptedPath(path, privkey=privkey)
    if binary:
        return epath.read_bytes()
    return epath.read_text()


# =============================================================================
# Re-export core functions for convenience
# =============================================================================

keygen = _core.keygen
encrypt = _core.encrypt
decrypt = _core.decrypt
sign = _core.sign
verify = _core.verify
armor = _core.armor
dearmor = _core.dearmor
Mobi521KeyPair = _core.Mobi521KeyPair
