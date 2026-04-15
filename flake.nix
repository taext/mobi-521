{
  description = "mobi-521: P-521 ECC encryption tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "mobi521";
          version = "0.6.2";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          cargoBuildFlags = [ "-p" "mobi521" ];

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            libx11
            libxcursor
            libxrandr
            libxi
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            wayland
            libxkbcommon
          ];

          meta = with pkgs.lib; {
            description = "P-521 elliptic curve encryption tool";
            homepage = "https://m521.app";
            license = licenses.mit;
            mainProgram = "mobi521";
          };
        };

        # Nightly toolchain for fuzzing
        devShells.fuzz = let
          toolchain = fenix.packages.${system}.complete.withComponents [
            "cargo"
            "rustc"
            "rust-src"
            "llvm-tools-preview"
          ];
        in pkgs.mkShell {
          buildInputs = [
            toolchain
            pkgs.cargo-fuzz
          ];
          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:$LD_LIBRARY_PATH"
            echo "Fuzz shell (nightly)"
            echo "  cd crates/core"
            echo "  cargo fuzz run fuzz_parse_format -- -max_total_time=60"
          '';
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          nativeBuildInputs = [
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.wasm-pack
            pkgs.maturin
            pkgs.lld
            pkgs.gcc
            pkgs.openssl
            (pkgs.python3.withPackages (ps: [ ps.pip ]))
            pkgs.wl-clipboard
            pkgs.libxkbcommon
            pkgs.wayland
            pkgs.nodejs  # For WASM tests
          ];
          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.wayland}/lib:${pkgs.libxkbcommon}/lib:$LD_LIBRARY_PATH"

            if [ -d ./target/release ]; then
              export PATH="$PWD/target/release:$PATH"
            fi

            # Python venv for maturin
            if [ ! -d .venv ]; then
              echo "Creating Python venv..."
              python -m venv .venv
            fi
            source .venv/bin/activate

            echo "mobi-521 dev shell"
            echo "  cargo build --release -p mobi521"
            echo "  wasm-pack build crates/wasm --target web --out-dir ../../web/pkg"
            echo "  cd crates/python && maturin develop --release"
          '';
        };
      });
}
