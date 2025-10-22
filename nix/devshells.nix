{ pkgs, system, common_packages, openssl_1_0_2, openssl_1_1_1, openssl_3_0
, aws-lc, aws-lc-fips-2022, aws-lc-fips-2024, writeScript }:

let
    commonShellHook = ''
      # Make libclang discoverable for bindgen
      export LIBCLANG_PATH="${pkgs.lib.getLib pkgs.llvmPackages_18.libclang}/lib"
      export LD_LIBRARY_PATH="$LIBCLANG_PATH:$LD_LIBRARY_PATH"
'';

  commonToolInputs = [
    pkgs.llvmPackages_18.clang
    pkgs.llvmPackages_18.libclang
    pkgs.cmake
    pkgs.rustc
    pkgs.cargo
  ];

  awsLcStatic = aws-lc.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or []) ++ [
      "-DBUILD_SHARED_LIBS=OFF"
    ];
  });
  
  awsLcFips2024Static = aws-lc-fips-2024.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or []) ++ [
      "-DBUILD_SHARED_LIBS=OFF"
    ];
  });

  # Define the default devShell
  default = pkgs.mkShell {
    # This is a development environment shell which should be able to:
    #  - build s2n-tls
    #  - run unit tests
    #  - run integ tests
    #  - do common development operations (e.g. lint, debug, and manage repos)
    inherit system;
    # keep minimal buildInputs; most tools come via `packages = common_packages`
    buildInputs = commonToolInputs ++ [ pkgs.cmake openssl_3_0 ];
    packages = common_packages;
    S2N_LIBCRYPTO = "openssl-3.0";
    # Only set OPENSSL_1_0_2_INSTALL_DIR when OpenSSL 1.0.2 is available
    OPENSSL_1_0_2_INSTALL_DIR =
      if openssl_1_0_2 != null then "${openssl_1_0_2}" else "";
    OPENSSL_1_1_1_INSTALL_DIR = "${openssl_1_1_1}";
    OPENSSL_3_0_INSTALL_DIR = "${openssl_3_0}";
    AWSLC_INSTALL_DIR = "${aws-lc}";
    AWSLC_FIPS_2022_INSTALL_DIR = "${aws-lc-fips-2022}";
    AWSLC_FIPS_2024_INSTALL_DIR = "${aws-lc-fips-2024}";
    # Integ s_client/server tests expect openssl 1.1.1.
    GNUTLS_INSTALL_DIR = "${pkgs.gnutls}";
    LIBRESSL_INSTALL_DIR = "${pkgs.libressl}";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      ${commonShellHook}
      # project shell script
      source ${writeScript ./shell.sh}
    '';
  };

  # Define the openssl111 devShell
  openssl111 = default.overrideAttrs (finalAttrs: previousAttrs: {
    # Re-include cmake to update the environment with a new libcrypto.
    buildInputs = commonToolInputs ++ [ pkgs.cmake openssl_1_1_1 ];
    S2N_LIBCRYPTO = "openssl-1.1.1";
    # Integ s_client/server tests expect openssl 1.1.1.
    # GnuTLS-cli and serv utilities needed for some integration tests.
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      ${commonShellHook}
      source ${writeScript ./shell.sh}
    '';
  });

  # Define the libressl devShell
  libressl_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    # Re-include cmake to update the environment with a new libcrypto.
    buildInputs = commonToolInputs ++ [ pkgs.cmake pkgs.libressl ];
    S2N_LIBCRYPTO = "libressl";
    # Integ s_client/server tests expect openssl 1.1.1.
    # GnuTLS-cli and serv utilities needed for some integration tests.
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      ${commonShellHook}
      source ${writeScript ./shell.sh}
    '';
  });

  openssl102 = default.overrideAttrs (finalAttrs: previousAttrs: {
    # Re-include cmake to update the environment with a new libcrypto.
    buildInputs = commonToolInputs ++ [ pkgs.cmake openssl_1_0_2 ];
    S2N_LIBCRYPTO = "openssl-1.0.2";
    # Integ s_client/server tests expect openssl 1.1.1.
    # GnuTLS-cli and serv utilities needed for some integration tests.
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      ${commonShellHook}
      source ${writeScript ./shell.sh}
    '';
  });

  # Define the awslc devShell
  awslc_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    # Re-include cmake to update the environment with a new libcrypto.
    buildInputs = commonToolInputs ++ [ pkgs.cmake awsLcStatic ];
    S2N_LIBCRYPTO = "awslc";
    # Integ s_client/server tests expect openssl 1.1.1.
    # GnuTLS-cli and serv utilities needed for some integration tests.
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      # Use static build (instead of default shared libs) for Rust internal libcrypto linkage
      export CMAKE_PREFIX_PATH="${awsLcStatic}''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
      ${commonShellHook}
      source ${writeScript ./shell.sh}
    '';
  });

  awslcfips2022_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    # Re-include cmake to update the environment with a new libcrypto.
    buildInputs = commonToolInputs ++ [ pkgs.cmake aws-lc-fips-2022 ];
    S2N_LIBCRYPTO = "awslc-fips-2022";
    # Integ s_client/server tests expect openssl 1.1.1.
    # GnuTLS-cli and serv utilities needed for some integration tests.
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      ${commonShellHook}
      source ${writeScript ./shell.sh}
    '';
  });

  awslcfips2024_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    # Re-include cmake to update the environment with a new libcrypto.
    buildInputs = commonToolInputs ++ [ pkgs.cmake awsLcFips2024Static ];
    S2N_LIBCRYPTO = "awslc-fips-2024";
    # Integ s_client/server tests expect openssl 1.1.1.
    # GnuTLS-cli and serv utilities needed for some integration tests.
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      # Use static build (instead of default shared libs) for Rust internal libcrypto linkage
      export CMAKE_PREFIX_PATH="${awsLcFips2024Static}''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
      ${commonShellHook}
      source ${writeScript ./shell.sh}
    '';
  });

in {
  default = default;
  openssl111 = openssl111;
  libressl = libressl_shell;
  openssl102 = openssl102;
  awslc = awslc_shell;
  awslcfips2022 = awslcfips2022_shell;
  awslcfips2024 = awslcfips2024_shell;
}