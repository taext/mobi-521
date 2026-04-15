{
  description = "mobi-521: P-521 ECC encryption tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "mobi521";
          version = "0.5.7";

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
