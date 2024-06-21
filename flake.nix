{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
  # TODO: https://github.com/aws/aws-lc/pull/830
  inputs.awslc.url = "github:dougch/aws-lc?ref=nixv1.17.4";

  outputs = { self, nix, nixpkgs, awslc, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        aws-lc = awslc.packages.${system}.aws-lc;
        # TODO: submit a flake PR
        corretto = import nix/amazon-corretto-17.nix { pkgs = pkgs; };
        # TODO: We have parts of our CI that rely on clang-format-15, but that is only available on github:nixos/nixpkgs/nixos-unstable
        llvmPkgs = pkgs.llvmPackages_14;
        pythonEnv = import ./nix/pyenv.nix { pkgs = pkgs; };
        # Note: we're rebuilding, not importing from nixpkgs for the mkShells.
        openssl_1_0_2 = import ./nix/openssl_1_0_2.nix { pkgs = pkgs; };
        openssl_1_1_1 = import ./nix/openssl_1_1_1.nix { pkgs = pkgs; };
        openssl_3_0 = import ./nix/openssl_3_0.nix { pkgs = pkgs; };
        libressl = import ./nix/libressl.nix { pkgs = pkgs; };
        common_packages = [
          # Integration Deps
          # We're not including openssl1.1.1 in our package list to avoid confusing cmake.
          # It will be in the PATH of our devShell for use in tests.
          pythonEnv
          pkgs.valgrind
          corretto
          pkgs.iproute2
          pkgs.apacheHttpd
          # GnuTLS-cli and serv utilities needed for some integration tests.
          pkgs.gnutls
          pkgs.gdb

          # C Compiler Tooling: llvmPkgs.clangUseLLVM -- wrapper to overwrite default compiler with clang
          llvmPkgs.llvm
          llvmPkgs.llvm-manpages
          llvmPkgs.libclang
          llvmPkgs.clang-manpages
          llvmPkgs.lldb

          # Linters/Formatters
          pkgs.shellcheck
          pkgs.nixfmt
          pkgs.python310Packages.pep8
          pkgs.python310Packages.ipython

          # Rust
          pkgs.rustup

          # Quality of Life
          pkgs.findutils
          pkgs.git
          pkgs.which
        ];
        writeScript = path:
          pkgs.writeScript (baseNameOf path) (builtins.readFile path);
      in rec {
        packages.s2n-tls = pkgs.stdenv.mkDerivation {
          src = self;
          name = "s2n-tls";
          inherit system;

          nativeBuildInputs = [ pkgs.cmake ];
          buildInputs = [ pkgs.openssl_3 ];

          configurePhase = ''
            cmake -S . -B./build \
                  -DBUILD_SHARED_LIBS=ON \
                  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                  -DS2N_NO_PQ=0
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

          propagatedBuildInputs = [ pkgs.openssl_3 ];
        };
        devShells.default = pkgs.mkShell {
          # This is a development environment shell which should be able to:
          #  - build s2n-tls
          #  - run unit tests
          #  - run integ tests
          #  - do common development operations (e.g. lint, debug, and manage repos)
          inherit system;
          buildInputs = [ pkgs.cmake openssl_3_0 ];
          packages = common_packages;
          S2N_LIBCRYPTO = "openssl-3.0";
          OPENSSL_1_0_2_INSTALL_DIR = "${openssl_1_0_2}";
          OPENSSL_1_1_1_INSTALL_DIR = "${openssl_1_1_1}";
          OPENSSL_3_0_INSTALL_DIR = "${openssl_3_0}";
          AWSLC_INSTALL_DIR = "${aws-lc}";
          GNUTLS_INSTALL_DIR = "${pkgs.gnutls}";
          LIBRESSL_INSTALL_DIR = "${libressl}";
          # Integ s_client/server tests expect openssl 1.1.1.
          shellHook = ''
            echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
            export PATH=${openssl_1_1_1}/bin:$PATH
            export PS1="[nix $S2N_LIBCRYPTO] $PS1"
            source ${writeScript ./nix/shell.sh}
          '';
        };

        devShells.openssl111 = devShells.default.overrideAttrs
          (finalAttrs: previousAttrs: {
            # Re-include cmake to update the environment with a new libcrypto.
            buildInputs = [ pkgs.cmake openssl_1_1_1 ];
            S2N_LIBCRYPTO = "openssl-1.1.1";
            # Integ s_client/server tests expect openssl 1.1.1.
            # GnuTLS-cli and serv utilities needed for some integration tests.
            shellHook = ''
              echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
              export PATH=${openssl_1_1_1}/bin:$PATH
              export PS1="[nix $S2N_LIBCRYPTO] $PS1"
              source ${writeScript ./nix/shell.sh}
            '';
          });

        devShells.libressl = devShells.default.overrideAttrs
          (finalAttrs: previousAttrs: {
            # Re-include cmake to update the environment with a new libcrypto.
            buildInputs = [ pkgs.cmake libressl ];
            S2N_LIBCRYPTO = "libressl";
            # Integ s_client/server tests expect openssl 1.1.1.
            # GnuTLS-cli and serv utilities needed for some integration tests.
            shellHook = ''
              echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
              export PATH=${openssl_1_1_1}/bin:$PATH
              export PS1="[nix $S2N_LIBCRYPTO] $PS1"
              source ${writeScript ./nix/shell.sh}
            '';
          });

        devShells.openssl102 = devShells.default.overrideAttrs
          (finalAttrs: previousAttrs: {
            # Re-include cmake to update the environment with a new libcrypto.
            buildInputs = [ pkgs.cmake openssl_1_0_2 ];
            S2N_LIBCRYPTO = "openssl-1.0.2";
            # Integ s_client/server tests expect openssl 1.1.1.
            # GnuTLS-cli and serv utilities needed for some integration tests.
            shellHook = ''
              echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
              export PATH=${openssl_1_1_1}/bin:$PATH
              export PS1="[nix $S2N_LIBCRYPTO] $PS1"
              source ${writeScript ./nix/shell.sh}
            '';
          });

        devShells.awslc = devShells.default.overrideAttrs
          (finalAttrs: previousAttrs: {
            # Re-include cmake to update the environment with a new libcrypto.
            buildInputs = [ pkgs.cmake aws-lc ];
            S2N_LIBCRYPTO = "awslc";
            # Integ s_client/server tests expect openssl 1.1.1.
            # GnuTLS-cli and serv utilities needed for some integration tests.
            shellHook = ''
              echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
              export PATH=${openssl_1_1_1}/bin:$PATH
              export PS1="[nix $S2N_LIBCRYPTO] $PS1"
              source ${writeScript ./nix/shell.sh}
            '';
          });

        # Used to backup the devShell to s3 for caching.
        packages.devShell = devShells.default.inputDerivation;
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
