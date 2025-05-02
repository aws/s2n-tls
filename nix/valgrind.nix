{ pkgs }:
# Check if we're on Linux or macOS
if pkgs.stdenv.isLinux then
  # Linux version
  pkgs.stdenv.mkDerivation rec {
    pname = "valgrind";
    version = "3.21.0"; # This is a stable version that should work

    src = pkgs.fetchurl {
      url = "https://sourceware.org/pub/valgrind/valgrind-${version}.tar.bz2";
      sha256 = "sha256-Yk9qPJfiGGd2LwJjgH9VLlDI8MhRvqx0aYOzUZSQJFU="; # SHA for 3.21.0
    };

    # Dependencies needed for valgrind
    nativeBuildInputs = [ pkgs.perl ] ++ (if pkgs.stdenv.isLinux then [ pkgs.gdb ] else [ ]);
    buildInputs = [ pkgs.glibc ];

    # Standard configure/make/install process
    configureFlags = [
      "--enable-only64bit"
      "--enable-lto=yes"
    ];

    # Ensure valgrind can find the debug info
    postInstall = ''
      for i in $out/lib/valgrind/*-*-linux; do
        ln -s $i $out/lib/valgrind/$(basename $i | sed 's/-linux$//')
      done
    '';

    # Disable broken meta attribute
    meta.broken = false;
  }
else
  # For macOS, just use the nixpkgs valgrind but override the broken attribute
  pkgs.valgrind.overrideAttrs (oldAttrs: {
    meta = oldAttrs.meta // { broken = false; };
  })
