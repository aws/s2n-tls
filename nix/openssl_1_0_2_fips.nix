{
  pkgs
}:
pkgs.stdenv.mkDerivation rec {
  pname = "openssl";
  version = "1.0.2-fips";

  src = fetchTarball {
    url = "https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-31_openssl-fips-2.0.13.tar.gz";
    sha256 = "";
  };

  buildInputs = [
    pkgs.gnumake
    pkgs.perl534
    # TODO: review install_openssl_1_0_2_fips.sh -- OpensslFipsModule doesn't make sense to me.
    (pkgs.stdenv.mkDerivation rec {
        pname = "OpensslFipsModule";
        version = "2017-08-31_2.0.13";
          src = fetchTarball {
            url = "https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-31_openssl-fips-2.0.13.tar.gz";
            sha256 = "";
          };
          configurePhase = ''
          ''

    })
  ];

  # TODO FIPSDIR
  configurePhase = ''
    ./config -d fips --with-fipsdir=$FIPSDIR shared -g3 -fPIC no-libunbound no-gmp no-jpake no-krb5 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-store no-zlib no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia no-bf no-ripemd no-dsa no-ssl2 no-capieng -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS --prefix="$out"
  '';

  buildPhase = ''
    make depend -j $(nproc)
    make -j $(nproc)
  '';

  installPhase = ''
    make install_sw
  '';
}
