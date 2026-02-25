# mobi-521 v0.5.5

<img src="mobi-521-logo-1.png" alt="mobi-521 logo" width="360" align="left" style="margin-right: 16px;">

A file encryption tool inspired by [age](https://age-encryption.org/), rebuilt on top of **P-521 elliptic-curve cryptography** instead of X25519/Ed25519. Not interoperable with age or rage.

**📚 [User Guide](https://v1d.dk/mobi-521/userguide.html) · 🌐 [Landing Page](https://v1d.dk/mobi-521/) · 🔗 [Try Web App](https://159.89.109.4/)**

<br clear="all">

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

**Nix (recommended):**
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

# Or without QR PNG support (smaller binary):
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
mobi521 keygen -o identity.txt        # save to file
mobi521 keygen --qr                   # with QR codes (ASCII)
mobi521 keygen --qr --qr-png mykey    # with PNG QR codes
mobi521 keygen --card-pdf card.pdf    # printable key card (A4, 2 cards)
mobi521 keygen --card-pdf card.pdf --single-card   # single card
mobi521 keygen --card-pdf card.pdf --dual-keys     # 2 different keypairs

# Encrypt a file
mobi521 encrypt -r mobi521... plaintext.txt -o encrypted.m521

# Decrypt a file
mobi521 decrypt -i identity.txt encrypted.m521 -o plaintext.txt

# Sign a file
mobi521 sign -i identity.txt document.txt -o document.sig

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
