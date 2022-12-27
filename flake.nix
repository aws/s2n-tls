{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-22.05;

  outputs = { self, nix, nixpkgs }: 
  let
     system = builtins.currentSystem or "x86_64-linux";
     pkgs = import nixpkgs { system = builtins.currentSystem or "x86_64-linux"; };
   in {
      packages.${system}.default = pkgs.stdenv.mkDerivation
      {
        src = self;
        name = "s2n-tls";
        inherit system; 
        doCheck = true;

        buildInputs = [ pkgs.cmake
                        pkgs.openssl ]; # s2n-config has find_dependency(LibCrypto

        cmakeFlags = [
            "-DBUILD_SHARED_LIBS=OFF"
            "-DUNSAFE_TREAT_WARNINGS_AS_ERRORS=OFF" # disable -Werror
            "-DS2N_NO_PQ=1"
        ];

      };
      devShell.x86_64-linux = 
        pkgs.mkShell { buildInputs = [ pkgs.openssl pkgs.cmake pkgs.gcc pkgs.clang pkgs.ninja ]; };
   };
 }
