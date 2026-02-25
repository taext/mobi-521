{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
          targets = [ "wasm32-unknown-unknown" "x86_64-unknown-linux-musl" "x86_64-pc-windows-gnu" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rust
            pkgs.wasm-pack
            pkgs.pkg-config
            pkgs.openssl
            pkgs.python3
            pkgs.wl-clipboard  # Wayland clipboard tool
            pkgs.libxkbcommon  # Wayland support
            pkgs.wayland       # Wayland libraries
            pkgs.musl          # Static linking for Linux deploy
            pkgs.pkgsCross.mingwW64.stdenv.cc  # Windows cross-compile
          ];
          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.wayland}/lib:${pkgs.libxkbcommon}/lib:$LD_LIBRARY_PATH"
            echo "mobi-521 dev shell"
            echo "  cargo build          -- native CLI"
            echo "  cargo check          -- type-check all crates"
            echo "  # Clipboard test:"
            echo "  echo 'test' | wl-copy && ./target/release/mobi521 encrypt"
            echo "  wasm-pack build crates/wasm --target web --out-dir ../../web/pkg"
            echo "  # Web UI:"
            echo "  docker build -f Dockerfile.web -t mobi521-web ."
            echo "  docker run --rm -p 8080:80 -p 8443:443 mobi521-web"
            echo "  # open https://localhost:8443"
          '';
        };
      });
}
