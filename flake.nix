{
  description = "A flake for s2n-tls";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    awslc.url = "github:dougch/aws-lc?ref=nixv1.36.0";
    awslcfips2022.url = "github:dougch/aws-lc?ref=nixAWS-LC-FIPS-2.0.17";
    awslcfips2024.url = "github:dougch/aws-lc?ref=nixfips-2024-09-27";
  };

  outputs =
    { self, nix, nixpkgs, awslc, awslcfips2022, awslcfips2024, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            permittedInsecurePackages = [
              "openssl-1.1.1w"
            ];
          };
        };
        # Internal variable = input.awslc ...<package name from flake>
        aws-lc = awslc.packages.${system}.aws-lc;
        # Only include aws-lc-fips on Linux platforms
        aws-lc-fips-2022 = if pkgs.stdenv.isLinux then
          awslcfips2022.packages.${system}.aws-lc-fips-2022
        else
          null;
        aws-lc-fips-2024 = if pkgs.stdenv.isLinux then
          awslcfips2024.packages.${system}.aws-lc-fips-2024
        else
          null;
        # TODO: submit a flake PR
        corretto = import nix/amazon-corretto-17.nix { pkgs = pkgs; };
        # TODO: We have parts of our CI that rely on clang-format-15, but that is only available on github:nixos/nixpkgs/nixos-unstable
        llvmPkgs = pkgs.llvmPackages_15;
        pythonEnv = import ./nix/pyenv.nix { pkgs = pkgs; };
        # Note: we're rebuilding, not importing from nixpkgs for the mkShells.
        # OpenSSL 1.0.2 is not supported on Apple Silicon (ARM64)
        openssl_1_0_2 = if pkgs.stdenv.isDarwin && pkgs.stdenv.isAarch64 then
          null
        else
          import ./nix/openssl_1_0_2.nix { pkgs = pkgs; };
        openssl_1_1_1 = import ./nix/openssl_1_1_1.nix { pkgs = pkgs; };
        openssl_3_0 = import ./nix/openssl_3_0.nix { pkgs = pkgs; };
        libressl = import ./nix/libressl.nix { pkgs = pkgs; };
        common_packages = [
          # Integration Deps
          # We're not including openssl1.1.1 in our package list to avoid confusing cmake.
          # It will be in the PATH of our devShell for use in tests.
          pythonEnv
          corretto
          # Only include iproute2 on Linux platforms
          (if pkgs.stdenv.isLinux then pkgs.iproute2 else null)
          pkgs.apacheHttpd
          pkgs.procps
          # GnuTLS-cli and serv utilities needed for some integration tests.
          pkgs.gnutls
          # Only include gdb on Linux platforms
          (if pkgs.stdenv.isLinux then pkgs.gdb else null)
          pkgs.tshark

          # C Compiler Tooling: Using GCC instead of Clang
          pkgs.gcc
          pkgs.gdb

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

          # Set GCC as the compiler for package builds
          CC = "${pkgs.gcc}/bin/gcc";
          CXX = "${pkgs.gcc}/bin/g++";

          nativeBuildInputs = [ pkgs.cmake ];
          buildInputs = [ pkgs.openssl_3 ];

          configurePhase = ''
            cmake -S . -B./build \
                  -DBUILD_SHARED_LIBS=ON \
                  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                  -DCMAKE_C_COMPILER=${pkgs.gcc}/bin/gcc \
                  -DCMAKE_CXX_COMPILER=${pkgs.gcc}/bin/g++
          ''; # Explicitly set GCC as the compiler for CMake

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
          # Only set OPENSSL_1_0_2_INSTALL_DIR when OpenSSL 1.0.2 is available
          OPENSSL_1_0_2_INSTALL_DIR =
            if openssl_1_0_2 != null then "${openssl_1_0_2}" else "";
          OPENSSL_1_1_1_INSTALL_DIR = "${openssl_1_1_1}";
          OPENSSL_3_0_INSTALL_DIR = "${openssl_3_0}";
          AWSLC_INSTALL_DIR = "${aws-lc}";
          AWSLC_FIPS_2022_INSTALL_DIR =
            if pkgs.stdenv.isLinux then "${aws-lc-fips-2022}" else "";
          AWSLC_FIPS_2024_INSTALL_DIR =
            if pkgs.stdenv.isLinux then "${aws-lc-fips-2024}" else "";

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

        # Only define openssl102 devShell when OpenSSL 1.0.2 is available (not on macOS ARM64)
        devShells.openssl102 = if openssl_1_0_2 != null then
          devShells.default.overrideAttrs (finalAttrs: previousAttrs: {
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
          })
        else
          null;

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
        # Only define awslcfips devShells on Linux platforms
        devShells = rec {
          inherit devShells;

          # Conditionally define awslcfips2022 devShell
          awslcfips2022 = if pkgs.stdenv.isLinux then
            devShells.default.overrideAttrs (finalAttrs: previousAttrs: {
              # Re-include cmake to update the environment with a new libcrypto.
              buildInputs = [ pkgs.cmake aws-lc-fips-2022 ];
              S2N_LIBCRYPTO = "awslc-fips-2022";
              AWSLC_FIPS_2022_INSTALL_DIR = "${aws-lc-fips-2022}";
              shellHook = ''
                echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
                export PATH=${openssl_1_1_1}/bin:$PATH
                export PS1="[nix $S2N_LIBCRYPTO] $PS1"
                source ${writeScript ./nix/shell.sh}
              '';
            })
          else
            null; # Used to backup the devShell to s3 for caching.

          # Conditionally define awslcfips2024 devShell
          awslcfips2024 = if pkgs.stdenv.isLinux then
            devShells.default.overrideAttrs (finalAttrs: previousAttrs: {
              # Re-include cmake to update the environment with a new libcrypto.
              buildInputs = [ pkgs.cmake aws-lc-fips-2024 ];
              S2N_LIBCRYPTO = "awslc-fips-2024";
              AWSLC_FIPS_2024_INSTALL_DIR = "${aws-lc-fips-2024}";
              shellHook = ''
                echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
                export PATH=${openssl_1_1_1}/bin:$PATH
                export PS1="[nix $S2N_LIBCRYPTO] $PS1"
                source ${writeScript ./nix/shell.sh}
              '';
            })
          else
            null; # Used to backup the devShell to s3 for caching.
        };
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
