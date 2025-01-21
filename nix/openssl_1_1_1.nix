{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "openssl";
  version = "1.1.1";

  src = pkgs.fetchzip {
    url =
      "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1t.zip";
    sha256 = "sha256-gI2+Vm67j1+xLvzBb+DF0YFTOHW7myotRsXRzluzSLY=";
  };

  buildInputs = [ pkgs.gnumake pkgs.perl534 pkgs.coreutils ];

  patchPhase = ''
    substitute ./config ./config --replace /usr/bin/env ${pkgs.coreutils}/bin/env
  '';

  configurePhase = ''
    ./config -d shared -g3 -fPIC              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=$out
  '';

  buildPhase = ''
    make depend -j $(nproc)
    make -j $(nproc)
  '';

  installPhase = ''
    make install_sw
  '';
}
