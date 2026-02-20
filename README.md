# mobi-521

<img src="mobi-521-logo-1.png" alt="mobi-521 logo" width="360" align="left" style="margin-right: 16px;">

A file encryption tool inspired by [age](https://age-encryption.org/), rebuilt on top of **P-521 elliptic-curve cryptography** instead of X25519/Ed25519. Not interoperable with age or rage.

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

## Installation

### With Nix (recommended)

```bash
nix develop        # enter dev shell (includes wl-clipboard for Wayland)
cargo build --release -p mobi521
./test_clipboard.sh auto  # run clipboard tests
```

The binary ends up at `target/release/mobi521`.

**Note:** On Wayland systems, clipboard support requires `wl-clipboard` to be installed. The Nix dev shell includes this automatically.

### With Docker (CLI)

```bash
docker build -t mobi521 .
docker run --rm mobi521 --help
```

Mount a local directory to encrypt/decrypt files:

```bash
docker run --rm -v "$PWD":/data mobi521 \
    encrypt -r <pubkey> /data/plaintext.txt -o /data/out.mobi521
```

### Web UI (Docker)

```bash
docker build -f Dockerfile.web -t mobi521-web .
docker run --rm -p 8080:80 -p 8443:443 mobi521-web
```

Open `https://localhost:8443` — runs entirely in the browser via WebAssembly, no data leaves your machine.

## Usage

### Generate a key pair

```bash
mobi521 keygen
# Public key: mobi521...
# MOBI521-SECRET-KEY-...

mobi521 keygen -o identity.txt   # write identity to file, print pubkey to stderr
```

### Encrypt

```bash
# From a file
mobi521 encrypt -r mobi521... plaintext.txt -o encrypted.mobi521

# From stdin
echo "secret" | mobi521 encrypt -r mobi521... -o encrypted.mobi521

# From clipboard (no input file specified)
# Copy text to clipboard, then:
mobi521 encrypt -r mobi521...
# Encrypted output is now in clipboard
```

If `-r` is omitted, mobi-521 looks for a default recipient key in:

```
$XDG_CONFIG_HOME/mobi521/default-recipient   # if XDG_CONFIG_HOME is set
~/.config/mobi521/default-recipient           # otherwise
```

The file should contain just the bech32m public key on a single line. This lets you encrypt to yourself without specifying `-r` every time:

```bash
# Set up once
mkdir -p ~/.config/mobi521
echo "mobi521..." > ~/.config/mobi521/default-recipient

# Then encrypt without -r
mobi521 encrypt secret.txt -o secret.txt.enc
```

### Decrypt

```bash
# Using an identity file
mobi521 decrypt -i identity.txt encrypted.mobi521

# Using a raw key string
mobi521 decrypt -i "MOBI521-SECRET-KEY-..." encrypted.mobi521 -o plaintext.txt

# From clipboard (no input file specified)
# Copy encrypted text to clipboard, then:
mobi521 decrypt -i identity.txt
# Decrypted plaintext is now in clipboard
```

### Clipboard Integration

mobi-521 automatically detects and uses the system clipboard when no input file is specified:

| Input | Output | Behavior |
|-------|--------|----------|
| No file (clipboard/stdin) | No `-o` flag | **Clipboard → Clipboard** (or stdin → clipboard if clipboard unavailable) |
| File specified | No `-o` flag | **File → stdout** (clipboard not used) |
| Any input | `-o` specified | **→ File** |

**Platform support:**
- **Wayland:** Uses `wl-clipboard` (`wl-copy` / `wl-paste`)
- **X11:** Uses native clipboard via `arboard`
- **macOS / Windows:** Uses native clipboard via `arboard`

**Automatic fallback:** If clipboard is unavailable, automatically falls back to stdin/stdout.

### Sign

```bash
mobi521 sign -i identity.txt document.txt -o document.sig
echo "hello" | mobi521 sign -i identity.txt
```

### Verify

```bash
mobi521 verify -p mobi521... -s document.sig document.txt
echo "hello" | mobi521 verify -p mobi521... -s <base64-sig>
```

## File format

```
mobi521.io/encrypted/v3\n
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

1. **Curve**: P-521 instead of X25519 / Ed25519.
2. **KDF**: HKDF-SHA512 instead of HKDF-SHA256.
3. **Format**: header stanza format is age-inspired but not spec-compliant.
4. **STREAM**: chunking matches the age approach (64 KiB, per-chunk AEAD) but the nonce derivation differs.
