{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "amazon-corretto";
  version = "8";

  src = pkgs.fetchzip {
    url =
      "https://corretto.aws/downloads/resources/8.362.08.1/amazon-corretto-8.362.08.1-linux-x64.tar.gz";
    sha256 = "sha256-VRGfnyW97gY8e/UlXbg6zlEThTTYdVc6BdMKhl1osVI=";
  };

  nativeBuildInputs = [ pkgs.autoPatchelfHook ];

  buildInputs = with pkgs; [
    alsa-lib
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
    mkdir $out
    cp -av ./* $out/
    echo $out after install
    ls $out/
  '';
}
