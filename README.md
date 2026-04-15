# mobi-521 v0.6.3

<img src="mobi-521-logo-kawaii.png" alt="mobi-521 logo" width="400" align="left" style="margin-right: 16px;">

A file encryption tool inspired by [age](https://age-encryption.org/), rebuilt on top of **P-521 elliptic-curve cryptography** instead of X25519/Ed25519. Not interoperable with age or rage.

**📚 [User Guide](https://v1d.dk/mobi-521/userguide.html) · 🌐 [Landing Page](https://v1d.dk/mobi-521/) · 🔗 [Try Web App](https://159.89.109.4/)**

<br clear="all">

## Contents

- [Crypto stack](#crypto-stack)
- [Quick Start](#quick-start)
  - [Installation](#installation)
  - [Basic Usage](#basic-usage)
  - [Default Keys](#default-keys)
  - [API Server](#api-server)
  - [WASM API](#wasm-api)
  - [Python API](#python-api)
- [File format](#file-format)
- [Workspace layout](#workspace-layout)
- [Divergences from the age spec](#divergences-from-the-age-spec)
- [Documentation](#documentation)
- [License](#license)

## Crypto stack

| Layer | Algorithm |
|-------|-----------|
| Key exchange | P-521 ECDH (ephemeral sender key + static recipient key) |
| Key derivation | HKDF-SHA512 |
| Symmetric encryption | ChaCha20-Poly1305 (STREAM construction, 64 KiB chunks) |
| Signing | ECDSA-P521-SHA512 (hedged nonce) |
| Key encoding | Bech32m (`mobi521…` public · `MOBI521-SECRET-KEY-…` private) |

The STREAM chunked construction means truncated ciphertexts always fail authentication — a chopped-off file cannot be decrypted as if it were complete.

## Quick Start

### Installation

**Nix (easiest):**
```bash
nix shell github:taext/mobi-521
mobi521 --help
```

**Nix (development):**
```bash
nix develop
cargo build --release -p mobi521
```

**Docker:**
```bash
docker build -t mobi521 .
docker run --rm mobi521 --help
```

**From source:**
```bash
cargo build --release -p mobi521

# Without API server (8.8 MB instead of 15 MB):
cargo build --release -p mobi521 --no-default-features --features "qr-png,pdf"

# Minimal build (no server, no QR PNG, no PDF):
cargo build --release -p mobi521 --no-default-features
```

**Web UI:** Try online at [https://159.89.109.4/](https://159.89.109.4/) or run locally:
```bash
docker build -f Dockerfile.web -t mobi521-web .
docker run --rm -p 8080:80 -p 8443:443 mobi521-web
```

### Basic Usage

```bash
# Generate a key pair
mobi521 keygen
mobi521 keygen -o identity.m521       # save to file
mobi521 keygen --qr                   # with QR codes (ASCII)
mobi521 keygen --qr --qr-png mykey    # with PNG QR codes
mobi521 keygen --card-pdf card.pdf    # printable key card (A4, 2 cards)
mobi521 keygen --card-pdf card.pdf --single-card   # single card
mobi521 keygen --card-pdf card.pdf --dual-keys     # 2 different keypairs

# Encrypt a file
mobi521 encrypt -r mobi521... plaintext.txt -o encrypted.m521

# Decrypt a file
mobi521 decrypt -i identity.m521 encrypted.m521 -o plaintext.txt

# Sign a file
mobi521 sign -i identity.m521 document.txt -o document.sig

# Verify a signature
mobi521 verify -p mobi521... -s document.sig document.txt
```

**Features:**
- Clipboard integration (Wayland/X11/macOS/Windows)
- QR codes for keys (ASCII terminal + optional PNG export)
- Printable key cards (A4 PDF, bifold design with QR codes)
- Default recipient configuration (`~/.config/mobi521/default-recipient`)
- Stdin/stdout piping support

**📚 See the [User Guide](web/userguide.html) for detailed documentation on all features.**

### Default Keys

Most encryption tools require you to specify keys every time. mobi-521 supports **default keys** so you can encrypt without flags:

```bash
# Instead of this every time:
mobi521 encrypt -r mobi5211q... diary.txt

# Just do this:
mobi521 encrypt diary.txt
```

**How it works:** mobi-521 looks for your default public key in these locations (first match wins):

| Priority | Location | Use case |
|----------|----------|----------|
| 1 | `MOBI521_PUBKEY` env var | CI/CD, scripts, temporary override |
| 2 | `~/.config/mobi521/default-recipient` | Personal default (recommended) |

**Setup (one time):**

```bash
# Generate a keypair
mobi521 keygen -o ~/.config/mobi521/identity

# Save public key as default recipient
grep "^mobi5211" ~/.config/mobi521/identity > ~/.config/mobi521/default-recipient
```

Now `mobi521 encrypt file.txt` encrypts to yourself automatically.

**Why this design?** Most personal encryption is *self-encryption* — protecting your own files, backups, and notes. The "recipient" is usually future-you. Default keys remove friction for the common case while still allowing explicit `-r` for sharing with others.

**For decryption**, you always need to specify your identity file with `-i` (private keys should never be "default" for security reasons).

### API Server

> **Note:** The API server is opt-in at build time. Default builds exclude it for a smaller binary (8.8 MB vs 15 MB). Build with `cargo build --release -p mobi521 --features server` to enable.

Start a local HTTP/HTTPS API server:

```bash
# HTTP
mobi521 serve --port 8080

# HTTPS (with TLS)
mobi521 serve --port 8443 --cert cert.pem --key key.pem
```

**Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/keygen` | Generate keypair |
| POST | `/api/encrypt` | Encrypt plaintext |
| POST | `/api/decrypt` | Decrypt ciphertext |
| POST | `/api/sign` | Sign message |
| POST | `/api/verify` | Verify signature |

**Example:**
```bash
curl -X POST http://localhost:8080/api/keygen
curl -X POST http://localhost:8080/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"recipient":"mobi521...", "plaintext":"Hello"}'
```

### WASM API

Use mobi-521 in the browser via WebAssembly. Build with:

```bash
wasm-pack build crates/wasm --target web --out-dir ../../web/pkg
```

**Functions:**

| Function | Parameters | Returns |
|----------|------------|---------|
| `keygen()` | — | `{ publicKey, privateKey }` |
| `encrypt(pubkey, data)` | bech32 pubkey, `Uint8Array` | ASCII-armored string |
| `decrypt(privkey, data)` | bech32 privkey, `Uint8Array` | `Uint8Array` |
| `sign(privkey, message)` | bech32 privkey, `Uint8Array` | base64 signature |
| `verify(pubkey, message, sig)` | bech32 pubkey, `Uint8Array`, base64 | `true` or throws |

**Example:**
```javascript
import init, { keygen, encrypt, decrypt, sign, verify } from './pkg/mobi521_wasm.js';

await init();

// Generate keypair
const { publicKey, privateKey } = keygen();

// Encrypt
const plaintext = new TextEncoder().encode("Hello, world!");
const ciphertext = encrypt(publicKey, plaintext);

// Decrypt
const decrypted = decrypt(privateKey, new TextEncoder().encode(ciphertext));
console.log(new TextDecoder().decode(decrypted));

// Sign & verify
const message = new TextEncoder().encode("Sign this");
const signature = sign(privateKey, message);
verify(publicKey, message, signature); // true or throws
```

### Python API

Native Python bindings via PyO3. Build with:

```bash
cd crates/python
maturin develop --release
```

**Core functions** (low-level, mirrors CLI):

```python
import mobi521

# Generate keypair
kp = mobi521.keygen()
print(kp.public_key)   # mobi5211q...
print(kp.private_key)  # MOBI521-SECRET-KEY1...

# Encrypt/decrypt
ciphertext = mobi521.encrypt(kp.public_key, b"secret message")
plaintext = mobi521.decrypt(kp.private_key, ciphertext)

# Sign/verify
signature = mobi521.sign(kp.private_key, b"document")
mobi521.verify(kp.public_key, b"document", signature)  # True or raises

# ASCII armor
armored = mobi521.armor(ciphertext)
raw = mobi521.dearmor(armored)
```

**Pythonic wrapper** (`mobi521_ext`) with pathlib-style API and context managers:

```python
from mobi521_ext import EncryptedPath, open as eopen, encrypt_to, decrypt_from

# Pathlib-style (uses default keys from config)
p = EncryptedPath("diary.m521")
p.write_text("Mine hemmeligheder")
print(p.read_text())

# Context managers
with eopen("config.m521", "w") as f:
    f.write("api_key=secret")

with eopen("config.m521", "r") as f:
    print(f.read())

# One-liners
encrypt_to("note.m521", "quick encryption")
content = decrypt_from("note.m521")

# Explicit keys
p = EncryptedPath("shared.m521", pubkey="mobi5211q...", privkey="MOBI521-SECRET-KEY1...")
```

**Key discovery** (same as CLI):

| Function | Env var | Config file |
|----------|---------|-------------|
| `load_default_pubkey()` | `MOBI521_PUBKEY` | `~/.config/mobi521/default-recipient` |
| `load_default_privkey()` | `MOBI521_PRIVKEY` | `~/.config/mobi521/default-identity` |

## File format

```
m521.app/encrypted/v3\n
-> p521 <bech32m-ephemeral-pubkey>\n
<base64(encrypted-file-key)>\n
---\n
<binary STREAM payload>
```

The payload is:

```
base_nonce (12 bytes)
|| ChaCha20-Poly1305(chunk_0)     # 64 KiB + 16-byte tag
|| ChaCha20-Poly1305(chunk_1)
|| ...
|| ChaCha20-Poly1305(final_chunk) # ≤ 64 KiB + 16-byte tag, final nonce
```

Per-chunk nonce = `base_nonce XOR (counter[8..12] || final_flag[7])`.

## Workspace layout

```
crates/core/   — crypto library (also compiled to WASM)
crates/cli/    — mobi521 binary
crates/wasm/   — wasm-bindgen exports for the browser UI
crates/python/ — PyO3 bindings + pythonic wrapper (mobi521_ext)
web/           — single-page browser UI (keygen / encrypt / decrypt / sign / verify)
```

## Divergences from the age spec

1. **Curve**: P-521 (2^521 - 1, a Mersenne prime) instead of X25519 / Ed25519
2. **KDF**: HKDF-SHA512 instead of HKDF-SHA256
3. **Format**: Header stanza format is age-inspired but not spec-compliant
4. **STREAM**: Chunking matches the age approach (64 KiB, per-chunk AEAD) but nonce derivation differs

## Documentation

- **[User Guide](web/userguide.html)** — Complete feature reference, CLI/Web UI usage, troubleshooting
- **[Landing Page](web/landing.html)** — Project overview, features, installation methods
- **[Changelog](CHANGELOG.md)** — Version history and breaking changes
- **[Web App](https://159.89.109.4/)** — Try mobi-521 in your browser (runs locally via WebAssembly)

## License

MIT — see [LICENSE](LICENSE) for details.
