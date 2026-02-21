# Changelog

All notable changes to mobi-521 will be documented in this file.

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
