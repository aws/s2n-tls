{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";

  outputs = { self, nix, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let upstreampkgs = nixpkgs.legacyPackages.${system};
      in rec {
        packages.s2n-tls = upstreampkgs.stdenv.mkDerivation {
          src = self;
          name = "s2n-tls";
          inherit system;

          nativeBuildInputs = [ upstreampkgs.cmake ];

          # Note: this version of openssl is 3 with nixos-22.11, 
          # but can change with different nixpkgs versions.
          buildInputs = [ upstreampkgs.openssl ];

          cmakeFlags = [
            "-DBUILD_SHARED_LIBS=ON"
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
            "-DS2N_NO_PQ=1" # TODO: set when system like aarch64/mips,etc
          ];

          propagatedBuildInputs = [
            upstreampkgs.openssl
          ]; # s2n-tls needs to be able to find libcrypto

        };
        packages.default = packages.s2n-tls;
        packages.s2n-tls-openssl3 = packages.s2n-tls.overrideAttrs
          (finalAttrs: previousAttrs: {
            doCheck = true;
            buildInputs = [
              upstreampkgs.openssl3
            ]; # redundant, but specifying version for consistency.
            propagatedBuildInputs = [ upstreampkgs.openssl3 ];
          });
        packages.s2n-tls-openssl11 = packages.s2n-tls.overrideAttrs
          (finalAttrs: previousAttrs: {
            doCheck = true;
            buildInputs = [ upstreampkgs.openssl_1_1 ];
            propagatedBuildInputs = [ upstreampkgs.openssl_1_1 ];
          });
        packages.s2n-tls-libressl = packages.s2n-tls.overrideAttrs
          (finalAttrs: previousAttrs: {
            doCheck = true;
            buildInputs = [ upstreampkgs.libressl ];
            propagatedBuildInputs = [ upstreampkgs.libressl ];
          });
        formatter = upstreampkgs.nixfmt;
      });
}
