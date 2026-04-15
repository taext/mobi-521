# Changelog

All notable changes to mobi-521 will be documented in this file.

## [0.6.2] - 2026-04-15

### Changed

- **Server feature no longer default** - HTTP server (`serve` command) now requires explicit opt-in
  - Default build: 8.7 MB (was 15 MB)
  - Build with server: `cargo build --release --features server`
  - 42% smaller binary for users who only need CLI encryption

## [0.6.1] - 2026-04-15

### Changed

- **New kawaii logo** - Updated logo across landing page, webapp, and README

## [0.6.0] - 2026-04-09

### Changed

- **Identity file extension** - Standardized to `.m521` across all documentation and webapp
  - Web app now downloads identity files as `identity.m521` (was `identity.m521key`)
  - Documentation examples updated: `identity.txt`, `identity.key`, `key.txt` → `identity.m521`, `key.m521`
  - Consistent with encrypted file extension (`.m521`)

## [0.5.8] - 2026-03-12

### Changed

- **Optional HTTP server** - API server is now a compile-time option
  - Default build includes server (15 MB)
  - Build without server: `--no-default-features --features "qr-png,pdf"` (8.8 MB)
  - 41% smaller binary when server is not needed
  - `serve` subcommand only available when `server` feature is enabled

## [0.5.7] - 2026-03-06

### Added

- **HTTP/HTTPS API server** - New `serve` subcommand starts a local REST API
  - `mobi521 serve --port 8080` - Start HTTP server
  - `mobi521 serve --port 8443 --cert cert.pem --key key.pem` - Start HTTPS server
  - Endpoints: `/api/health`, `/api/keygen`, `/api/encrypt`, `/api/decrypt`, `/api/sign`, `/api/verify`
  - JSON request/response format
  - Built with axum and rustls

## [0.5.6] - 2026-02-26

### Added

- **Shell completion support** - New `completions` subcommand generates tab completion scripts
  - Supports Bash, Zsh, Fish, Elvish, and PowerShell
  - `mobi521 completions fish > ~/.config/fish/completions/mobi521.fish`
- **`--message` / `-m` flag for encrypt** - Encrypt strings directly without file/stdin
  - `mobi521 encrypt -m "secret note"` - Encrypts the string directly
  - Conflicts with file input (use one or the other)
- **Piping support** - Automatic stdin/stdout detection for pipeline workflows
- **Author attribution** - Version output now shows author contact

### Changed

- **Landing page reframing** - "Self-encryption first" philosophy
  - New tagline: "Protect your thoughts and files"
  - Emphasis on personal file protection over communication
  - "Write-only mailbox to yourself" concept

## [0.5.5] - 2026-02-25

### Added

- **Multi-platform CLI executables** - GitHub Actions workflow builds release binaries for:
  - Linux x86_64 (musl, static, works on all distros including NixOS)
  - Linux ARM64 (Raspberry Pi, ARM servers)
  - Windows x86_64
  - macOS Apple Silicon (M1/M2/M3/M4)
- **Nix flake cross-compile support** - `x86_64-unknown-linux-musl` target for portable Linux builds

## [0.4.5] - 2026-02-24

### Added

- **`export-pdf` command** - Generate printable key card PDFs from existing identity files
  - `mobi521 export-pdf --identity identity.m521` - Create PDF from existing key
  - Accepts both file paths and raw key strings (like decrypt/sign commands)
  - Supports `--single-card` and `--dual-keys` flags
  - Default output: `keycard.pdf`

## [0.4.4] - 2026-02-22

### Added

- **Printable key cards** - Generate professional A4 PDF key cards for physical backup and key exchange
  - Bifold design (210×148.5mm per card, folds at 105mm)
  - Public key (green QR) and private key (red QR) with bech32 strings
  - Three CLI variants: `--card-pdf` (2 identical cards), `--card-pdf --single-card` (1 card), `--card-pdf --dual-keys` (2 different keypairs)
  - Web UI: "Download Key Card PDF" button generates matching PDFs in browser
  - Scandinavian minimal design with proper typography and spacing
  - Blank KEY NAME field for manual labeling
  - Stippled cut line for easy separation of duplicate cards

## [0.4.3] - 2026-02-21

### Added

- **Defense in Depth documentation** - Comprehensive guide to layered encryption strategies
  - Detailed section in User Guide explaining mobi-521 + Signal/WhatsApp workflows
  - Comparison table: Signal only vs Signal + mobi-521
  - Use cases for journalists, whistleblowers, legal professionals, healthcare, activists
  - Alternative secure channels (messaging, email, cloud, physical media, QR codes)
  - Prominent callout box on landing page
  - Security considerations in ECC Explained page
  - Zero trust transport model explanation

- **ECC Explained page** - Pedagogical introduction to elliptic curve cryptography
  - 11 detailed sections building from basics to advanced topics
  - Visual ASCII diagrams explaining curve operations and protocols
  - ECDH and ECDSA protocols explained step-by-step
  - Comparison table: P-521 vs X25519, Ed25519, secp256k1
  - Security considerations including quantum threats
  - Math notation blocks and pedagogical callouts
  - Further reading resources (books, RFCs, papers, online)

### Changed

- QR PNG support now enabled by default (from v0.4.2)
- Updated all documentation to reflect PNG as default feature
- Streamlined installation instructions

### Documentation

- Added comprehensive defense in depth strategies across all pages
- Cross-linked all documentation pages for easy navigation
- Positions mobi-521 as ideal for high-security scenarios

## [0.4.2] - 2026-02-21

### Changed

- **QR PNG support now enabled by default** - The `qr-png` feature is now part of default features
  - No longer need to build with `--features qr-png`
  - `--qr-png` flag available out of the box
  - Users can opt-out with `--no-default-features` for smaller binary
  - Updated all documentation to reflect this change

### Documentation

- Updated installation instructions across README, user guide, and landing page
- Changed "optional feature" language to "included by default" with opt-out option
- Updated troubleshooting section for QR PNG availability

## [0.4.1] - 2026-02-21

### Added

- **Landing page** - Professional presentation page (`web/landing.html`)
  - Modern marketing-focused design with light/dark theme support
  - Feature showcase grid highlighting P-521, STREAM, QR codes, signatures
  - CLI vs Web comparison section with code examples
  - Complete cryptographic stack specification
  - Installation guides for Nix, Docker, and source builds
  - Defaults to light mode with persistent theme preference

- **Comprehensive user guide** - Complete reference documentation (`web/userguide.html`)
  - 14 detailed sections covering all features
  - Sticky sidebar navigation with smooth scrolling
  - Installation, CLI usage, QR codes, encryption, decryption, signatures
  - Clipboard integration guide with platform-specific details
  - Web UI security model and features
  - File format specification and security considerations
  - Troubleshooting section for common issues
  - Light/dark theme support (defaults to light mode)

### Changed

- **README.md streamlined** - Reduced from ~200 lines to 127 lines
  - Now serves as quick reference with links to detailed documentation
  - Removed duplicate content covered in user guide
  - Added prominent links to landing page, user guide, and web app
  - Kept essential crypto stack, file format, and workspace layout
  - Added Mersenne prime notation (2^521 - 1) in divergences section

- **HTTPS server improvements** - Added cache-control headers to prevent aggressive browser caching
  - `Cache-Control: no-cache, no-store, must-revalidate`
  - `Pragma: no-cache`
  - `Expires: 0`
  - Fixes Firefox redirect caching issues

### Documentation

- Landing page provides professional overview and feature highlights
- User guide serves as complete reference with troubleshooting
- README.md now focuses on quick start and references detailed docs
- All documentation pages cross-link for easy navigation
- Consistent version numbers across all files (v0.4.1)

## [0.4.0] - 2026-02-21

### Added

- **CLI QR code support** - Generate QR codes for key pairs
  - `--qr` flag displays ASCII QR codes in terminal (zero dependencies, works over SSH)
  - `--qr-png <prefix>` saves QR codes as PNG files (requires `--features qr-png` at build time)
  - Generates QR codes for both public and private keys
  - Security warning displayed when showing private key QR codes
  - PNG images are 200×200 pixels, matching the web UI
  - Uses `qrcode` crate v0.14 for generation
  - Optional `image` crate v0.25 for PNG support

- **HTTPS server for web UI** - Simple Python HTTPS server (`web/https_server.py`)
  - Serves web UI over HTTPS (port 443 by default)
  - SSL certificate support for secure local hosting
  - Useful for deployment without Docker

### Changed

- **BREAKING: File extension changed** from `.mobi521` to `.m521` (shorter, cleaner)
  - Updated all documentation and examples
  - Updated web UI file picker and download buttons
  - Identity files now download as `.m521key`
  - QR code downloads now use `m521-public-key.png` and `m521-private-key.png`

- **BREAKING: Protocol magic string** changed from `mobi521.io/encrypted/v3` to `m521.app/encrypted/v3`
  - Invalidates all existing v3 encrypted files
  - HKDF domain tag updated to match new magic string
  - Pre-1.0 breaking changes are expected

### Fixed

- Removed duplicate public key output in `keygen` command when run without `-o` flag

### Documentation

- Updated `README.md` with QR code usage examples
- Added build instructions for optional PNG support
- Updated file format documentation with new magic string

## [0.3.1] - 2026-02-20

### Added

- **Clipboard integration** - Automatic clipboard support for encrypt/decrypt operations
  - When no input file is specified, mobi521 reads from clipboard (with automatic fallback to stdin)
  - When no input file is specified and no `-o` flag, output goes to clipboard (with automatic fallback to stdout)
  - When input file is specified, output goes to stdout (not clipboard) unless `-o` is used

- **Wayland support** - Full clipboard support for Wayland environments
  - Uses `wl-clipboard` (`wl-copy` / `wl-paste`) on Wayland systems
  - Automatic detection via `WAYLAND_DISPLAY` environment variable
  - Falls back to `arboard` for X11, macOS, and Windows

- **Smart clipboard behavior**
  - Clipboard → Clipboard: `mobi521 encrypt` (no files)
  - File → stdout: `mobi521 encrypt file.txt` (no `-o` flag)
  - File → File: `mobi521 encrypt file.txt -o out.txt`

### Changed

- Updated `crates/cli/Cargo.toml` - Added `arboard = "3.4"` dependency
- Updated `flake.nix` - Added Wayland dependencies (`wl-clipboard`, `libxkbcommon`, `wayland`)
- Enhanced `test_clipboard.sh` - Now tests all three input/output scenarios (clipboard→clipboard, file→stdout, file→file)
- Improved error messages - More descriptive clipboard error messages with fallback notifications

### Documentation

- Updated `README.md` with comprehensive clipboard documentation
  - Added clipboard examples for encrypt/decrypt operations
  - Added clipboard integration behavior table
  - Added platform support section (Wayland, X11, macOS, Windows)
  - Updated installation notes for Wayland systems

## [0.3.0] - Previous release

See git history for earlier changes.
