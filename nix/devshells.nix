{ pkgs, system, common_packages, openssl_1_0_2, openssl_1_1_1, openssl_3_0
, aws-lc, aws-lc-fips-2022, aws-lc-fips-2024, writeScript }:

let
  rustShellHook = ''
    # Explicitly set LIBCLANG_PATH so clang-sys (used by bindgen) can locate libclang inside the Nix store.
    # Unlike normal C/C++ builds, bindgen loads libclang dynamically with dlopen(), not via the compiler wrapper
    # or LD_LIBRARY_PATH. Setting this ensures bindgen always finds the correct Nix-provided libclang,
    # even though mkShell’s buildInputs already include it.
    export LIBCLANG_PATH="${pkgs.lib.getLib pkgs.llvmPackages_18.libclang}/lib"
    # Bindgen bypasses cc-wrapper, so give it the same flags/paths cc-wrapper would add
    export BINDGEN_EXTRA_CLANG_ARGS="$(< ${pkgs.stdenv.cc}/nix-support/libc-crt1-cflags) \
      $(< ${pkgs.stdenv.cc}/nix-support/libc-cflags) \
      $(< ${pkgs.stdenv.cc}/nix-support/cc-cflags) \
      $(< ${pkgs.stdenv.cc}/nix-support/libcxx-cxxflags) \
      ${
        pkgs.lib.optionalString pkgs.stdenv.cc.isClang
        "-idirafter ${pkgs.stdenv.cc.cc}/lib/clang/${
          pkgs.lib.getVersion pkgs.stdenv.cc.cc
        }/include"
      } \
      ${
        pkgs.lib.optionalString pkgs.stdenv.cc.isGNU
        "\n        -isystem ${pkgs.stdenv.cc.cc}/include/c++/${
                  pkgs.lib.getVersion pkgs.stdenv.cc.cc
                } \n        -isystem ${pkgs.stdenv.cc.cc}/include/c++/${
                  pkgs.lib.getVersion pkgs.stdenv.cc.cc
                }/${pkgs.stdenv.hostPlatform.config} \n        -idirafter ${pkgs.stdenv.cc.cc}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${
                  pkgs.lib.getVersion pkgs.stdenv.cc.cc
                }/include\n      "
      }"
  '';

  # Base tool inputs for different development scenarios
  rustToolInputs = [
    pkgs.llvmPackages_18.clang
    pkgs.llvmPackages_18.libclang
    pkgs.llvmPackages_18.bintools
    pkgs.cmake
    pkgs.rustc
    pkgs.rustup
    pkgs.cargo
  ];

  # Helper function to create base shell configurations
  mkBaseShell =
    { withRustTools ? false, cryptoLib, libcryptoName, extraCMakeFlags ? "" }:
    pkgs.mkShell {
      inherit system;
      buildInputs = [ pkgs.cmake cryptoLib ]
        ++ (if withRustTools then rustToolInputs else [ ]);
      packages = if withRustTools then [ ] else common_packages;
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
        ${if withRustTools then "export S2N_RUST_MODE=1" else ""}
        ${extraCMakeFlags}
        ${rustShellHook}
        source ${writeScript ./shell.sh}
      '';
    };

  # By default, AWS-LC’s flake build produces shared libraries (.so).
  # However, s2n-tls’s “intern libcrypto” mode statically links AWS-LC into the binary
  # instead of dynamically linking at runtime. To support that, we override the default
  # AWS-LC build to produce static libraries
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
