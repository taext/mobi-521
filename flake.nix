{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.wasm-pack
            pkgs.gcc
            pkgs.openssl
            pkgs.python3
            pkgs.wl-clipboard
            pkgs.libxkbcommon
            pkgs.wayland
          ];
          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.wayland}/lib:${pkgs.libxkbcommon}/lib:$LD_LIBRARY_PATH"

            # Add local build to PATH so completions work in nix develop
            if [ -d ./target/release ]; then
              export PATH="$PWD/target/release:$PATH"
            fi

            echo "mobi-521 dev shell"
            echo "  cargo build --release -p mobi521   -- CLI binary"
            echo "  wasm-pack build crates/wasm --target web --out-dir ../../web/pkg"
            echo "  scp -r web/* root@159.89.109.4:/root/mobi521-web/"
          '';
        };
      });
}
