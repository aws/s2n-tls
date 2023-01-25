{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-22.11;

  outputs = { self, nix, nixpkgs, flake-utils }: 
     flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
   in rec {
      packages.s2n-tls = pkgs.stdenv.mkDerivation {
        src = self;
        name = "s2n-tls";
        inherit system; 
        # TODO: override the s2n-tls version

        buildInputs = [ pkgs.cmake
                        pkgs.openssl_3 ]; # s2n-config has find_dependency LibCrypto

        cmakeFlags = [
            "-DBUILD_SHARED_LIBS=ON"
            "-DUNSAFE_TREAT_WARNINGS_AS_ERRORS=OFF" # disable -Werror
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
            "-DS2N_NO_PQ=1" # TODO: set when system like aarch64/mips,etc
        ];

      };
      defaultPackage = packages.s2n-tls;
      packages.s2n-tls-openssl3 = pkgs.s2n-tls.overrideAttrs (finalAttrs: previousAttrs: {
        doCheck = true;
      });
      packages.s2n-tls-openssl11 = pkgs.s2n-tls.overrideAttrs (finalAttrs: previousAttrs: {
        doCheck = true;
        buildInputs = [ pkgs.openssl_1_1 ];
      });
      # TODO: s2n_crl_test fails on libressl-3.6.1
      packages.s2n-tls-libressl = pkgs.s2n-tls.overrideAttrs (finalAttrs: previousAttrs: {
        doCheck = true;
        buildInputs = [ pkgs.libressl ];
      });
      # TODO: boringssl shared lib not being installed by default
      packages.s2n-tls-boringssl = pkgs.s2n-tls.overrideAttrs (finalAttrs: previousAttrs: {
        doCheck = true;
        buildInputs = [ pkgs.boringssl ];
      });
      # TODO: not linking correctly, missing .so as well?
      packages.s2n-tls-gnutls = pkgs.s2n-tls.overrideAttrs (finalAttrs: previousAttrs: {
        doCheck = true;
        buildInputs = [ pkgs.gnutls ];
      });
   });
 }
