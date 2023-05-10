# Present as a historical record.
# Only needed if https://github.com/aws/s2n-tls/issues/3810 is resolved.
{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "openssl";
  version = "0.9.8";

  src = fetchTarball {
    url = "https://www.openssl.org/source/old/0.9.x/openssl-0.9.8zh.tar.gz";
    sha256 = "sha256:0h451dgk2pws957cjidjhwb2qlr0qx73klzb0n0l3x601jmw27ih";
  };

  buildInputs = [ pkgs.gnumake pkgs.perl534 ];

  configurePhase = ''
    ./config --prefix=$out
  '';

  buildPhase = ''
    make depend -j $(nproc)
    make -j $(nproc)
  '';

  installPhase = ''
    make install
  '';
}
