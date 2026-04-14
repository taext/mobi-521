use mobi521_core::keys::{encode_public_key, encode_secret_key, KeyPair};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// A P-521 key pair.
#[pyclass]
#[derive(Clone)]
pub struct Mobi521KeyPair {
    #[pyo3(get)]
    pub public_key: String,
    #[pyo3(get)]
    pub private_key: String,
}

#[pymethods]
impl Mobi521KeyPair {
    fn __repr__(&self) -> String {
        format!(
            "Mobi521KeyPair(public_key='{}...', private_key='[REDACTED]')",
            &self.public_key[..20]
        )
    }
}

/// Generate a new P-521 key pair.
///
/// Returns a Mobi521KeyPair with public_key and private_key attributes.
///
/// Example:
///     >>> kp = mobi521.keygen()
///     >>> print(kp.public_key)
///     mobi5211q...
#[pyfunction]
fn keygen() -> Mobi521KeyPair {
    let kp = KeyPair::generate();
    Mobi521KeyPair {
        public_key: encode_public_key(&kp.public),
        private_key: encode_secret_key(&kp.secret),
    }
}

/// Encrypt data for a recipient's public key.
///
/// Args:
///     recipient_pubkey: The recipient's bech32-encoded public key (mobi5211q...)
///     data: The plaintext bytes to encrypt
///
/// Returns:
///     The encrypted ciphertext as bytes.
///
/// Example:
///     >>> ciphertext = mobi521.encrypt(public_key, b"secret message")
#[pyfunction]
fn encrypt<'py>(py: Python<'py>, recipient_pubkey: &str, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let ct = mobi521_core::encrypt(recipient_pubkey, data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &ct))
}

/// Decrypt ciphertext using a private key.
///
/// Args:
///     private_key: The bech32-encoded private key (MOBI521-SECRET-KEY-...)
///     data: The ciphertext bytes (raw or ASCII-armored)
///
/// Returns:
///     The decrypted plaintext as bytes.
///
/// Example:
///     >>> plaintext = mobi521.decrypt(private_key, ciphertext)
#[pyfunction]
fn decrypt<'py>(py: Python<'py>, private_key: &str, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let pt = mobi521_core::decrypt(private_key, data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &pt))
}

/// Sign a message with a private key.
///
/// Args:
///     private_key: The bech32-encoded private key
///     message: The message bytes to sign
///
/// Returns:
///     A base64-encoded ECDSA-P521-SHA512 signature string.
///
/// Example:
///     >>> signature = mobi521.sign(private_key, b"message to sign")
#[pyfunction]
fn sign(private_key: &str, message: &[u8]) -> PyResult<String> {
    mobi521_core::sign(private_key, message)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Verify a signature against a message using a public key.
///
/// Args:
///     public_key: The bech32-encoded public key
///     message: The original message bytes
///     signature: The base64-encoded signature string
///
/// Returns:
///     True if the signature is valid.
///
/// Raises:
///     ValueError: If the signature is invalid.
///
/// Example:
///     >>> mobi521.verify(public_key, b"message", signature)
///     True
#[pyfunction]
fn verify(public_key: &str, message: &[u8], signature: &str) -> PyResult<bool> {
    mobi521_core::verify(public_key, message, signature)
        .map(|_| true)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// ASCII-armor ciphertext for safe text transport.
///
/// Args:
///     data: Raw ciphertext bytes
///
/// Returns:
///     ASCII-armored string with BEGIN/END markers.
///
/// Example:
///     >>> armored = mobi521.armor(ciphertext)
///     >>> print(armored)
///     -----BEGIN MOBI521 ENCRYPTED FILE-----
///     ...
///     -----END MOBI521 ENCRYPTED FILE-----
#[pyfunction]
fn armor(data: &[u8]) -> String {
    mobi521_core::armor::armor(data)
}

/// Remove ASCII armor from ciphertext.
///
/// Args:
///     data: ASCII-armored ciphertext string
///
/// Returns:
///     Raw ciphertext bytes.
#[pyfunction]
fn dearmor<'py>(py: Python<'py>, data: &str) -> PyResult<Bound<'py, PyBytes>> {
    let raw = mobi521_core::armor::dearmor(data.as_bytes())
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &raw))
}

/// mobi-521: P-521 elliptic curve encryption for Python.
///
/// A Python binding for mobi-521, providing:
/// - Key generation (P-521 ECDH)
/// - Encryption (ChaCha20-Poly1305 STREAM)
/// - Decryption
/// - Signing (ECDSA-P521-SHA512)
/// - Signature verification
/// - ASCII armor encoding/decoding
#[pymodule]
fn mobi521(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Mobi521KeyPair>()?;
    m.add_function(wrap_pyfunction!(keygen, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(armor, m)?)?;
    m.add_function(wrap_pyfunction!(dearmor, m)?)?;
    Ok(())
}
