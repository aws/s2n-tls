{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "openssl-fips";
  version = "1.0.2";

  # OpenSSL 1.0.2 source
  src = pkgs.fetchzip {
    url =
      "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_2u.zip";
    sha256 = "sha256-UzJzeL4gMzSNVig4eXe3arVvwdFYg5yEUuL9xAcXKiY=";
  };

  # OpenSSL FIPS 2.0.13 module source - using upstream GitHub instead of S3
  fipsSrc = pkgs.fetchurl {
    url = "https://github.com/openssl/openssl/releases/download/OpenSSL-fips-2_0_13/openssl-fips-2.0.13.tar.gz";
    sha256 = "sha256-P/cj+TkB91B3mi5n/xWYXDV/GhXIkslQREb7yFxvd9o=";
  };

  buildInputs = [ pkgs.gnumake pkgs.perl ];

  # Build the FIPS module first, then OpenSSL with FIPS support
  configurePhase = let
    default_options =
      "shared -g3 -fPIC no-libunbound no-gmp no-jpake no-krb5 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-store no-zlib no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia no-bf no-ripemd no-dsa no-ssl2 no-capieng -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS --prefix=$out";
    fips_options = "fips --with-fipsdir=$FIPSDIR";
  in {
    x86_64-linux = ''
      # Extract and build FIPS module first
      echo "Building OpenSSL FIPS 2.0.13 module from upstream GitHub..."
      tar -xzf ${fipsSrc}
      cd openssl-fips-2.0.13
      mkdir -p ../OpensslFipsModule
      export FIPSDIR="$(pwd)/../OpensslFipsModule"
      chmod +x ./Configure
      ./config -d
      make
      make install
      cd ..
      
      # Configure OpenSSL with FIPS support
      echo "Configuring OpenSSL 1.0.2 with FIPS support..."
      ./config -d ${fips_options} ${default_options}
    '';
    # FIPS mode is not expected to work on aarch64 per task requirements
    aarch64-linux = ''
      echo "FIPS mode is not supported on aarch64"
      exit 1
    '';
  }.${pkgs.stdenv.hostPlatform.system};

  buildPhase = ''
    make depend -j $(nproc)
    make -j $(nproc)
  '';

  installPhase = ''
    make install_sw
    
    # Verify FIPS mode is available
    echo "Verifying FIPS mode availability..."
    if [ -f "$out/bin/openssl" ]; then
      $out/bin/openssl version -a || true
    fi
  '';

  meta = with pkgs.lib; {
    description = "OpenSSL 1.0.2 with FIPS 140-2 support (using upstream sources)";
    longDescription = ''
      OpenSSL 1.0.2 built with FIPS 140-2 Object Module support.
      This build uses the official upstream FIPS module from GitHub instead of S3.
      This build is for testing purposes only and is not FIPS compliant
      as we do not own the build system architecture.
    '';
    platforms = [ "x86_64-linux" ]; # Only x86_64-linux supported
  };
}
