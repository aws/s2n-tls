{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "openssl";
  version = "1.0.2";

  src = pkgs.fetchzip {
    url =
      "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_2u.zip";
    sha256 = "sha256-UzJzeL4gMzSNVig4eXe3arVvwdFYg5yEUuL9xAcXKiY=";
  };

  buildInputs = [ pkgs.gnumake pkgs.perl534 ];

  configurePhase = let
    default_options =
      "shared -g3 -fPIC no-libunbound no-gmp no-jpake no-krb5 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-store no-zlib no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia no-bf no-ripemd no-dsa no-ssl2 no-capieng -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS --prefix=$out";
  in {
    x86_64-linux = ''
      ./config -d ${default_options}
    '';
    # The Openssl102 Configure script appears to have a bug and won't recognize
    # aarch64 as a supported platform when passed the '-d' flag.
    # See the PR for more detail: https://github.com/aws/s2n-tls/pull/4045 
    aarch64-linux = ''
      ./config ${default_options}
    '';
    x86_64-darwin = ''
      # TODO: validation in future PR - nix checks fail without a definition.
      ./config -d ${default_options}
    '';
    aarch64-darwin = ''
      # TODO: validation in future PR - nix checks fail without a definition.
      ./config ${default_options}
    '';
  }.${pkgs.stdenv.hostPlatform.system};

  buildPhase = ''
    make depend -j $(nproc)
    make -j $(nproc)
  '';

  installPhase = ''
    make install_sw
  '';
}
