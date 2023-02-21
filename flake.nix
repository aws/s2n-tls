{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";

  outputs = { self, nix, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # TODO: We have parts of our CI that rely on clang-format-15, but that is only avalible on github:nixos/nixpkgs/nixos-unstable
        llvmPkgs = pkgs.llvmPackages_14;
        pythonEnv = import ./nix/pyenv.nix { pkgs = pkgs; };
        openssl_0_9_8 = import ./nix/openssl_0_9_8.nix { pkgs = pkgs; };
        openssl_1_0_2 = import ./nix/openssl_1_0_2.nix { pkgs = pkgs; };
        openssl_1_1_1 = import ./nix/openssl_1_1_1.nix { pkgs = pkgs; };
        openssl_3_0 = import ./nix/openssl_3_0.nix { pkgs = pkgs; };
        libressl = import ./nix/libressl.nix { pkgs = pkgs; };
        corretto-8 = import nix/amazon-corretto-8.nix { pkgs = pkgs; };
        gnutls-3-7 = import nix/gnutls.nix { pkgs = pkgs; };
        writeScript = path:
          pkgs.writeScript (baseNameOf path) (builtins.readFile path);
      in rec {
        packages.s2n-tls = pkgs.stdenv.mkDerivation {
          src = self;
          name = "s2n-tls";
          inherit system;

          nativeBuildInputs = [ pkgs.cmake ];
          buildInputs = [ pkgs.openssl ];

          configurePhase = ''
            cmake -S . -B./build \
                  -DBUILD_SHARED_LIBS=ON \
                  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                  -DS2N_NO_PQ=1
          ''; # TODO: set when system like aarch64/mips,etc

          buildPhase = ''
            cmake --build ./build -j $(nproc)
          '';

          installPhase = ''
            cmake --install ./build --prefix $out
          '';

          checkPhase = ''
            echo Not running tests here. Run `nix develop` to run tests.
          '';

          propagatedBuildInputs = [ pkgs.openssl ];
        };
        devShells.default = pkgs.mkShell {
          # This is a development enviroment shell which should be able to:
          #  - build s2n-tls
          #  - run unit tests
          #  - run integ tests
          #  - do common development operations (e.g. lint, debug, and manage repos)
          inherit system;
          shellHook = ''
            echo Setting up enviornment from flake.nix...
            export S2N_LIBCRYPTO=openssl-1.1.1
            export PATH=${
              self.packages.${system}.s2n-tls
            }/bin:${openssl_1_1_1}/bin:${gnutls-3-7}/bin:$PATH
            export PS1="[nix] $PS1"
            alias openssl-098=${openssl_0_9_8}/bin/openssl
            alias openssl-102=${openssl_1_0_2}/bin/openssl
            alias openssl-30=${openssl_3_0}/bin/openssl
            source ${writeScript ./nix/shell.sh}
          '';
          packages = [
            # Build Depends
            openssl_1_1_1
            pkgs.cmake
            # Other Libcryptos
            openssl_0_9_8
            openssl_1_0_2
            openssl_3_0
            libressl
            pkgs.boringssl

            # Integration Deps
            pythonEnv
            corretto-8
            gnutls-3-7

            # C Compiler Tooling: llvmPkgs.clangUseLLVM -- wrapper to overwrite default compiler with clang
            llvmPkgs.llvm
            llvmPkgs.llvm-manpages
            llvmPkgs.libclang
            llvmPkgs.clang-manpages

            # Linters/Formatters
            pkgs.shellcheck
            pkgs.cppcheck
            pkgs.nixfmt
            pkgs.python39Packages.pep8

            # Rust
            pkgs.rustup

            # Quality of Life
            pkgs.findutils
            pkgs.git
            pkgs.which
          ];
        };
        packages.default = packages.s2n-tls;
        packages.s2n-tls-openssl3 = packages.s2n-tls.overrideAttrs
          (finalAttrs: previousAttrs: { doCheck = true; });
        packages.s2n-tls-openssl11 = packages.s2n-tls.overrideAttrs
          (finalAttrs: previousAttrs: {
            doCheck = true;
            buildInputs = [ pkgs.openssl_1_1 ];
          });
        packages.s2n-tls-libressl = packages.s2n-tls.overrideAttrs
          (finalAttrs: previousAttrs: {
            doCheck = true;
            buildInputs = [ pkgs.libressl ];
          });
        formatter = pkgs.nixfmt;
      });
}
