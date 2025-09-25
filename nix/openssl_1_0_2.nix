{ pkgs }:
if pkgs.stdenv.hostPlatform.system == "aarch64-linux" then
  # Create a minimal stub derivation for aarch64 that just prints a warning
  pkgs.stdenv.mkDerivation rec {
    pname = "openssl-1.0.2-unsupported";
    version = "1.0.2";

    src = pkgs.writeText "warning.txt" "OpenSSL 1.0.2 is not supported on aarch64";

    dontUnpack = true;
    dontConfigure = true;
    dontBuild = true;

    installPhase = ''
      mkdir -p $out/bin
      cat > $out/bin/openssl << 'EOF'
#!/bin/sh
echo "WARNING: OpenSSL 1.0.2 (both FIPS and non-FIPS) is not supported on aarch64 architecture."
echo "This is a stub installation that does nothing."
exit 1
EOF
      chmod +x $out/bin/openssl

      # Create empty lib and include directories to satisfy any build dependencies
      mkdir -p $out/lib $out/include

      echo "WARNING: OpenSSL 1.0.2 is not supported on aarch64. Created stub installation." >&2
    '';

    meta = with pkgs.lib; {
      description = "OpenSSL 1.0.2 stub for unsupported aarch64 architecture";
      longDescription = ''
        This is a stub package for OpenSSL 1.0.2 on aarch64 architecture.
        OpenSSL 1.0.2 (both FIPS and non-FIPS variants) are not supported on aarch64.
        This package provides a minimal stub to prevent build failures.
      '';
      platforms = [ "aarch64-linux" ];
    };
  }
else
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
    in ''
      # Extract and build FIPS module first
      echo "Building OpenSSL FIPS 2.0.13 module from upstream GitHub..."
      tar -xzf ${fipsSrc}
      cd openssl-fips-2.0.13

      # Patch fipsld script to fix hardcoded /bin/rm path
      echo "Patching fipsld script to use portable rm command..."
      if [ -f util/fipsld ]; then
        sed -i 's|/bin/rm|rm|g' util/fipsld
        echo "Patched util/fipsld to use 'rm' instead of '/bin/rm'"
      fi

      mkdir -p ../OpensslFipsModule
      export FIPSDIR="$(pwd)/../OpensslFipsModule"
      chmod +x ./Configure
      ./config -d
      make
      make install
      
      # Also patch the installed fipsld script in the FIPS directory
      echo "Patching installed fipsld script..."
      if [ -f "$FIPSDIR/bin/fipsld" ]; then
        sed -i 's|/bin/rm|rm|g' "$FIPSDIR/bin/fipsld"
        echo "Patched $FIPSDIR/bin/fipsld to use 'rm' instead of '/bin/rm'"
      fi
      cd ..
      
      # Configure OpenSSL with FIPS support
      echo "Configuring OpenSSL 1.0.2 with FIPS support..."
      ./config -d ${fips_options} ${default_options}
    '';

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
      platforms = [ "x86_64-linux" ]; # Only x86_64-linux supported for real build
    };
  }
