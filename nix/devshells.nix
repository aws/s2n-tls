{ pkgs, system, common_packages, openssl_1_0_2, openssl_1_1_1, openssl_3_0
, aws-lc, aws-lc-fips-2022, aws-lc-fips-2024, writeScript }:

let
  rustShellHook = ''
    # Make libclang discoverable for bindgen
    export LIBCLANG_PATH="${pkgs.lib.getLib pkgs.llvmPackages_18.libclang}/lib"
    export LD_LIBRARY_PATH="$LIBCLANG_PATH:$LD_LIBRARY_PATH"
  '';

  # Base tool inputs for different development scenarios
  rustToolInputs = [
    pkgs.llvmPackages_18.clang
    pkgs.llvmPackages_18.libclang
    pkgs.llvmPackages_18.bintools
    pkgs.cmake
    pkgs.rustc
    pkgs.cargo
  ];

  # Helper function to create base shell configurations
  mkBaseShell =
    { withRustTools ? false, cryptoLib, libcryptoName, extraCMakeFlags ? "" }:
    pkgs.mkShell {
      inherit system;
      buildInputs = [ pkgs.cmake cryptoLib ]
        ++ (if withRustTools then rustToolInputs else [ ]);
      packages = common_packages;
      S2N_LIBCRYPTO = libcryptoName;
      # Environment variables for all crypto libraries
      OPENSSL_1_0_2_INSTALL_DIR =
        if openssl_1_0_2 != null then "${openssl_1_0_2}" else "";
      OPENSSL_1_1_1_INSTALL_DIR = "${openssl_1_1_1}";
      OPENSSL_3_0_INSTALL_DIR = "${openssl_3_0}";
      AWSLC_INSTALL_DIR = "${aws-lc}";
      AWSLC_FIPS_2022_INSTALL_DIR = "${aws-lc-fips-2022}";
      AWSLC_FIPS_2024_INSTALL_DIR = "${aws-lc-fips-2024}";
      GNUTLS_INSTALL_DIR = "${pkgs.gnutls}";
      LIBRESSL_INSTALL_DIR = "${pkgs.libressl}";
      shellHook = ''
        echo Setting up $S2N_LIBCRYPTO${
          if withRustTools then " + Rust" else ""
        } environment from flake.nix...
        export PATH=${openssl_1_1_1}/bin:$PATH
        export PS1="[nix${
          if withRustTools then " rust" else ""
        } $S2N_LIBCRYPTO] $PS1"
        ${extraCMakeFlags}
        ${rustShellHook}
        source ${writeScript ./shell.sh}
      '';
    };

  awsLcStatic = aws-lc.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or [ ]) ++ [ "-DBUILD_SHARED_LIBS=OFF" ];
  });

  awsLcFips2024Static = aws-lc-fips-2024.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or [ ]) ++ [ "-DBUILD_SHARED_LIBS=OFF" ];
  });

  # Standard devshells (common_packages only)
  default = mkBaseShell {
    cryptoLib = openssl_3_0;
    libcryptoName = "openssl-3.0";
  };

  openssl102 = mkBaseShell {
    cryptoLib = openssl_1_0_2;
    libcryptoName = "openssl-1.0.2";
  };

  openssl111 = mkBaseShell {
    cryptoLib = openssl_1_1_1;
    libcryptoName = "openssl-1.1.1";
  };

  libressl_shell = mkBaseShell {
    cryptoLib = pkgs.libressl;
    libcryptoName = "libressl";
  };

  awslc_shell = mkBaseShell {
    cryptoLib = aws-lc;
    libcryptoName = "awslc";
  };

  awslcfips2022_shell = mkBaseShell {
    cryptoLib = aws-lc-fips-2022;
    libcryptoName = "awslc-fips-2022";
  };

  awslcfips2024_shell = mkBaseShell {
    cryptoLib = aws-lc-fips-2024;
    libcryptoName = "awslc-fips-2024";
  };

  # Rust-enabled devshells (common_packages + rustToolInputs)
  rust_openssl102 = mkBaseShell {
    withRustTools = true;
    cryptoLib = openssl_1_0_2;
    libcryptoName = "openssl-1.0.2";
  };

  rust_openssl111 = mkBaseShell {
    withRustTools = true;
    cryptoLib = openssl_1_1_1;
    libcryptoName = "openssl-1.1.1";
  };

  rust_openssl30 = mkBaseShell {
    withRustTools = true;
    cryptoLib = openssl_3_0;
    libcryptoName = "openssl-3.0";
  };

  rust_awslc = mkBaseShell {
    withRustTools = true;
    cryptoLib = awsLcStatic;
    libcryptoName = "awslc";
    extraCMakeFlags = ''
      export CMAKE_PREFIX_PATH="${awsLcStatic}''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"'';
  };

  rust_awslcfips2024 = mkBaseShell {
    withRustTools = true;
    cryptoLib = awsLcFips2024Static;
    libcryptoName = "awslc-fips-2024";
    extraCMakeFlags = ''
      export CMAKE_PREFIX_PATH="${awsLcFips2024Static}''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"'';
  };

in {
  # Standard devshells (common_packages only)
  default = default;
  openssl102 = openssl102;
  openssl111 = openssl111;
  libressl = libressl_shell;
  awslc = awslc_shell;
  awslcfips2022 = awslcfips2022_shell;
  awslcfips2024 = awslcfips2024_shell;

  # Rust-enabled devshells (common_packages + rustToolInputs)
  rust_openssl102 = rust_openssl102;
  rust_openssl111 = rust_openssl111;
  rust_openssl30 = rust_openssl30;
  rust_awslc = rust_awslc;
  rust_awslcfips2024 = rust_awslcfips2024;
}
