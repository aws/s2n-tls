{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";

  outputs = { self, nix, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
      in rec {
        packages.s2n-tls = pkgs.stdenv.mkDerivation {
          src = self;
          name = "s2n-tls";
          inherit system;

          nativeBuildInputs = [ pkgs.cmake ];
          buildInputs = [ pkgs.openssl ];

          cmakeFlags = [
            "-DBUILD_SHARED_LIBS=ON"
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
            "-DS2N_NO_PQ=1" # TODO: set when system like aarch64/mips,etc
          ];

          propagatedBuildInputs = [ pkgs.openssl ];

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
