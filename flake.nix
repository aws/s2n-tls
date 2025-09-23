{
  description = "A flake for s2n-tls";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    # Pure nix functions, not relying on nixpkgs https://github.com/numtide/flake-utils
    flake-utils.url = "github:numtide/flake-utils";
    awslc.url = "github:aws/aws-lc";
    awslcfips2022.url = "github:dougch/aws-lc?ref=nixAWS-LC-FIPS-2.0.17";
    awslcfips2024.url = "github:dougch/aws-lc?ref=nixfips-2024-09-27";
  };

  outputs = { self, nixpkgs, awslc, awslcfips2022, awslcfips2024, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = { permittedInsecurePackages = [ "openssl-1.1.1w" ]; };
        };
        # Internal variable = input.awslc ...<package name from flake>
        aws-lc = awslc.packages.${system}.aws-lc;
        aws-lc-fips-2022 = awslcfips2022.packages.${system}.aws-lc-fips-2022;
        aws-lc-fips-2024 = awslcfips2024.packages.${system}.aws-lc-fips-2024;
        # Note: we're rebuilding, not importing from nixpkgs for the mkShells.
        openssl_1_0_2 = import ./nix/openssl_1_0_2.nix { pkgs = pkgs; };
        openssl_1_1_1 = import ./nix/openssl_1_1_1.nix { pkgs = pkgs; };
        openssl_3_0 = import ./nix/openssl_3_0.nix { pkgs = pkgs; };
        common_packages = [
          # Integration Deps
          # We're not including openssl1.1.1 in our package list to avoid confusing cmake.
          # It will be in the PATH of our devShell for use in tests.
          pkgs.corretto21
          pkgs.iproute2
          pkgs.apacheHttpd
          pkgs.procps
          # stress testing tool for linux
          pkgs.stress
          # GnuTLS-cli and serv utilities needed for some integration tests.
          pkgs.gnutls
          pkgs.tshark

          # C Compiler Tooling; adding llvm/clang is an involved future task.
          pkgs.gcc
          pkgs.gdb
          pkgs.valgrind

          # Linters/Formatters
          pkgs.shellcheck
          # There are 2 nix formatters; use the old one for now.
          pkgs.nixfmt-classic
          # Let uv handle all the python things.
          pkgs.uv

          # Rust
          pkgs.rustup

          # Quality of Life
          pkgs.findutils
          pkgs.git
          pkgs.which
        ];
        writeScript = path:
          pkgs.writeScript (baseNameOf path)
          (builtins.readFile (toString path));
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
        # Import devShells from the separate module
        devShells = import ./nix/devshells.nix {
          inherit pkgs system common_packages openssl_1_0_2 openssl_1_1_1
            openssl_3_0 aws-lc aws-lc-fips-2022 aws-lc-fips-2024 writeScript;
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
        formatter = pkgs.nixfmt;
      });
}
