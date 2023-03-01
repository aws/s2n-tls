{ pkgs }:
let nettle = (import ./nettle.nix { pkgs = pkgs; });
in pkgs.stdenv.mkDerivation rec {
  pname = "gnutls";
  version = "3.7.3";

  src = fetchTarball {
    url =
      "https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2022-01-18_gnutls-3.7.3.tar.xz";
    sha256 = "sha256:07rk09hz138m0l5vrvymyj2z2is92mwykqzzf81d8xgbpn2dyapc";
  };

  buildInputs = [ nettle pkgs.m4 pkgs.pkg-config pkgs.gmpxx ];

  configurePhase = ''
    export PKG_CONFIG_PATH=${nettle}/lib/pkgconfig:$PKG_CONFIG_PATH
    ./configure --prefix="$out" \
                --without-p11-kit \
                --with-included-libtasn1 \
                --with-included-unistring
  '';

  buildPhase = ''
    make -j $(nproc)
  '';

  installPhase = ''
    make -j $(nproc) install
  '';
}
