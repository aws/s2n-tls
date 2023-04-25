{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "amazon-corretto";
  version = "17";
  # From https://docs.aws.amazon.com/corretto/latest/corretto-17-ug/downloads-list.html
  src = let uri = "https://corretto.aws/downloads";
  in {
    x86_64-linux = pkgs.fetchzip {
      url = "${uri}/latest/amazon-corretto-17-x64-linux-jdk.tar.gz";
      sha256 = "sha256-DEkfpGiqcas4HcAc327uMZj5BDR29JYSP0g4sEbFVSU=";
    };
    aarch64-linux = pkgs.fetchzip {
      url = "${uri}/latest/amazon-corretto-17-aarch64-linux-jdk.tar.gz";
      sha256 = "sha256-DvL/1F1FD7bksodDNNJL+lKBMWOPuYdOihJ/CQxosNU=";
    };
    # TODO: The Mac versions will be validated in future darwin PR - nix still wants them defined.
    x86_64-darwin = pkgs.fetchzip {
      url = "${uri}/latest/amazon-corretto-17-x64-macos-jdk.tar.gz";
      sha256 = "sha256-DvL/1F1FD7bksodDNNJL+lKBMWOPuYdOihJ/CQxosNU=";
    };
    aarch64-darwin = pkgs.fetchzip {
      url = "${uri}/latest/amazon-corretto-17-x64-macos-jdk.tar.gz";
      sha256 = "sha256-DvL/1F1FD7bksodDNNJL+lKBMWOPuYdOihJ/CQxosNU=";
    };
  }.${pkgs.stdenv.hostPlatform.system} or (throw
    "Unsupported system: ${pkgs.stdenv.hostPlatform.system}");

  # See: https://github.com/NixOS/patchelf/issues/10
  dontStrip = 1;

  nativeBuildInputs = if (pkgs.stdenv.system == "x86_64-linux") then [
    pkgs.autoPatchelfHook
    pkgs.alsa-lib
  ] else
    [ ];

  buildInputs = with pkgs; [
    cpio
    file
    which
    zip
    perl
    zlib
    cups
    freetype
    harfbuzz
    libjpeg
    giflib
    libpng
    zlib
    lcms2
    fontconfig
    glib
    xorg.libX11
    xorg.libXrender
    xorg.libXext
    xorg.libXtst
    xorg.libXt
    xorg.libXtst
    xorg.libXi
    xorg.libXinerama
    xorg.libXcursor
    xorg.libXrandr
    gtk2-x11
    gdk-pixbuf
    xorg.libXxf86vm
  ];

  buildPhase = ''
    echo "Corretto is already built"
  '';

  installPhase = ''
    mkdir -p $out/nix-support
    cp -av ./* $out/
    ln -s $out/Contents/Home/* $out/

    # Remove some broken manpages/demo.
    rm -rf $out/Home/man/ja*
    rm -rf $out/Home/demo

    # Set JAVA_HOME automatically.
    cat <<EOF >> $out/nix-support/setup-hook
    if [ -z "\''${JAVA_HOME-}" ]; then export JAVA_HOME=$out; fi
    EOF
  '';
}
