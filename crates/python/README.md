# mobi521

P-521 elliptic curve encryption for Python.

## Installation

```bash
pip install mobi521
```

Or build from source with [maturin](https://github.com/PyO3/maturin):

```bash
cd crates/python
maturin develop
```

## Usage

```python
import mobi521

# Generate a key pair
kp = mobi521.keygen()
print(kp.public_key)   # mobi5211q...
print(kp.private_key)  # MOBI521-SECRET-KEY-...

# Encrypt data
ciphertext = mobi521.encrypt(kp.public_key, b"secret message")

# ASCII armor for text transport
armored = mobi521.armor(ciphertext)
print(armored)

# Decrypt
plaintext = mobi521.decrypt(kp.private_key, ciphertext)
assert plaintext == b"secret message"

# Sign and verify
signature = mobi521.sign(kp.private_key, b"message")
mobi521.verify(kp.public_key, b"message", signature)  # returns True
```

## API

- `keygen()` - Generate a P-521 key pair
- `encrypt(public_key, data)` - Encrypt bytes for a recipient
- `decrypt(private_key, data)` - Decrypt ciphertext
- `sign(private_key, message)` - Sign a message (ECDSA-P521-SHA512)
- `verify(public_key, message, signature)` - Verify a signature
- `armor(data)` - ASCII-armor ciphertext
- `dearmor(text)` - Remove ASCII armor

## Crypto Stack

- **Key exchange**: P-521 ECDH
- **Key derivation**: HKDF-SHA512
- **Encryption**: ChaCha20-Poly1305 STREAM
- **Signatures**: ECDSA-P521-SHA512

## License

MIT
