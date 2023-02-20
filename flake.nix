{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";

  outputs = { self, nix, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
          # TODO: We have parts of our CI that rely on clang-format-15, but that is only avalible on github:nixos/nixpkgs/nixos-unstable
          llvmPkgs = pkgs.llvmPackages_14;
          pythonEnv = import ./nix/pyenv.nix { pkgs = pkgs; };
          openssl_0_9_8 = import ./nix/openssl_0_9_8.nix {pkgs=pkgs;};
          openssl_1_0_2 = import ./nix/openssl_1_0_2.nix {pkgs=pkgs;};
          openssl_1_1_1 = import ./nix/openssl_1_1_1.nix {pkgs=pkgs;};
          openssl_3_0 = import ./nix/openssl_3_0.nix {pkgs=pkgs;};
          libressl = import ./nix/libressl.nix {pkgs=pkgs;};
          corretto-8 = import nix/amazon-corretto-8.nix {pkgs=pkgs; };
          gnutls-3-7 = import nix/gnutls.nix {pkgs=pkgs;};
 
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
               echo Entering a integration test enviorment
               export S2N_LIBCRYPTO=openssl-1.1.1
               export PATH=${self.packages.${system}.s2n-tls}/bin:${openssl_1_1_1}/bin:${gnutls-3-7}/bin:$PATH
               export SRC_ROOT=$(pwd)

               banner()
               {
                 echo "+------------------------------------------+"
                 printf "| %-40s |\n" "$1"
                 echo "+------------------------------------------+"
               }


               function configure {
                 banner "Configuring with cmake"
                 cmake -S . -B./build \
                   -DBUILD_TESTING=ON \
                   -DS2N_INTEG_TESTS=ON \
                   -DS2N_INSTALL_S2NC_S2ND=ON \
                   -DS2N_NIX_FAST_INTEG_TESTS=ON \
                   -DBUILD_SHARED_LIBS=ON \
                   -DCMAKE_BUILD_TYPE=RelWithDebInfo
               }
               
               function build {
                 banner "Running Build"
                 javac tests/integrationv2/bin/SSLSocketClient.java
                 cmake --build ./build -j $(nproc)
               }

               function unit {
                 cd build
                 if [[ -z "$1" ]]; then
                  ctest -L unit -j $(nproc) --verbose
                 else
                  ctest -L unit -R $1 -j $(nproc) --verbose
                 fi
                 cd ../
               }
               
               function integ {
                 if [ "$1" == "help" ]; then
                    echo "The following tests are not supported:"
                    echo " - cross_compatibility"
                    echo "    This test depends on s2nc_head and s2nd_head. To run"
                    echo "    the test build s2n-tls from the main branch on github."
                    echo "    Change the names of s2n[cd] to s2n[cd]_head and add those"
                    echo "    binaries to \$PATH."
                    echo "- renegotiate_apache"
                    echo "   This test requires apache to be running. See codebuild/bin/s2n_apache.sh"
                    echo "    for more info."
                    return
                 fi
                 if [[ -z "$1" ]]; then
                  banner "Running all integ tests except cross_compatibility, renegotiate_apache."
                  (cd $SRC_ROOT/build; ctest -L integrationv2 -E "(integrationv2_cross_compatibility|integrationv2_renegotiate_apache)" --verbose)
                 else
                  banner "Warning: cross_compatibility & renegotiate_apache are not supported in nix for various reasons integ help for more info."
                  (cd $SRC_ROOT/build; ctest -L integrationv2 -R "$1" --verbose)
                 fi
               }
               
               function check-clang-format {
                 banner "Dry run of clang-format"
                 cd $SRC_ROOT
                 include_regex=".*\.(c|h)$"
                 src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
		             echo $src_files | xargs -n 1 -P $(nproc) clang-format --dry-run -style=file                 
               }
              function do-clang-format {
                 banner "In place clang-format"
                 cd $SRC_ROOT
                 include_regex=".*\.(c|h)$"
                 src_files=`find ./api -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./bin -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./crypto -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./stuffer -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./error -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./tls -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./utils -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./tests/unit -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
                 src_files+=" "
                 src_files+=`find ./tests/testlib -name .git -prune -o -regextype posix-egrep -regex "$include_regex" -print`
		             echo $src_files | xargs -n 1 -P $(nproc) clang-format -style=file -i
               }
          '';

          packages = [
            # Build Depends
            openssl_1_1_1 pkgs.cmake
            # Other Libcryptos
            # openssl_0_9_8 openssl_1_0_2 openssl_3_0
            # libressl pkgs.boringssl

            # Integration Deps
            pythonEnv corretto-8 gnutls-3-7

            # C Compiler Tooling: llvmPkgs.clangUseLLVM -- wrapper to overwrite default compiler with clang
            llvmPkgs.llvm llvmPkgs.llvm-manpages llvmPkgs.libclang llvmPkgs.clang-manpages 

            # Linters/Formatters
            pkgs.shellcheck pkgs.cppcheck pkgs.nixfmt pkgs.python39Packages.pep8

            # Rust
            # TODO: can we use the version in bindings/rust/rust-toolchain
            # it goes against the spirit of nix to use rustup... but we might
            # have to -- using a new rust is liable to get us in trouble.
            pkgs.rustc pkgs.cargo

            # Quality of Life
            pkgs.findutils
            pkgs.git
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
