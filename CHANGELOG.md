# Changelog

All notable changes to mobi-521 will be documented in this file.

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
