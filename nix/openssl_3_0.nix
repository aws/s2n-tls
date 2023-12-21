{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "openssl";
  version = "3.0.12";

  src = pkgs.fetchzip {
    url =
      "https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.12.zip";
    sha256 = "sha256-UOTgvfmOG8vEFIlIJcoxJ0SEqntcDUYDJ2phCfPLQ7A=";
  };

  buildInputs = [ pkgs.gnumake pkgs.perl538 ];

  patchPhase = ''
    substitute ./Configure ./Configure --replace /usr/bin/env ${pkgs.coreutils}/bin/env
  '';

  configurePhase = ''
    ./Configure shared -g3 -fPIC              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng no-dtls          \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=$out
  '';

  buildPhase = ''
    make -j $(nproc)
  '';

  installPhase = ''
    make install
  '';
}
