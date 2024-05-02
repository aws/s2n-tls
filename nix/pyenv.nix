{ pkgs }:
let
  pythonPkgs = pkgs.python310Packages;
  cryptography = pythonPkgs.cryptography;
  pyOpenSSL = pythonPkgs.pyopenssl;
in pkgs.python310.withPackages (ps: [
  ps.pep8
  ps.pytest
  ps.pytest-xdist
  ps.pytest-rerunfailures
  ps.typing-extensions
  ps.setuptools-rust
  ps.cryptography
])

