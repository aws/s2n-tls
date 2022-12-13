{
  description = "A flake for s2n-tls";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-22.05;

  outputs = { self, nixpkgs }: {

    defaultPackage.x86_64-linux =
      # Notice the reference to nixpkgs here.
      with import nixpkgs { system = "x86_64-linux"; };
      stdenv.mkDerivation {
        name = "s2n-tls";
        src = self;
        doCheck = true;

        buildInputs = [ pkgs.cmake
                        pkgs.openssl ]; # s2n-config has find_dependency(LibCrypto

        cmakeFlags = [
            "-DBUILD_SHARED_LIBS=OFF"
            "-DUNSAFE_TREAT_WARNINGS_AS_ERRORS=OFF" # disable -Werror
            "-DS2N_NO_PQ=1"
        ];

      };

  };
}
