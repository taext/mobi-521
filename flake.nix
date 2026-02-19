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
          targets = [ "wasm32-unknown-unknown" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rust
            pkgs.wasm-pack
            pkgs.pkg-config
            pkgs.openssl
            pkgs.python3
          ];
          shellHook = ''
            echo "mobi-521 dev shell"
            echo "  cargo build          -- native CLI"
            echo "  cargo check          -- type-check all crates"
            echo "  wasm-pack build crates/wasm --target web --out-dir ../../web/pkg"
            echo "  # Web UI:"
            echo "  docker build -f Dockerfile.web -t mobi521-web ."
            echo "  docker run --rm -p 8080:80 -p 8443:443 mobi521-web"
            echo "  # open https://localhost:8443"
          '';
        };
      });
}
