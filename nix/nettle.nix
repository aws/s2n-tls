{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "nettle";
  version = "3.7";

  src = fetchTarball {
    name = "nettle";
    url =
      "https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2021-01-04_nettle-3.7.tar.gz";
    sha256 = "sha256:0xxfxd6hb20qjc6q9nji4pcn0lm8zjvrdpx4knbmmx7fqax0ddb9";
  };

  buildInputs = [ pkgs.gmpxx pkgs.m4 ];

  configurePhase = ''
    ./configure --prefix=$out/ \
             --disable-openssl \
             --enable-shared
  '';

  buildPhase = ''
    make -j $(nproc)
  '';

  installPhase = ''
    make -j $(nproc) install
  '';

}
