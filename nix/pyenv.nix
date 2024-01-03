{ pkgs }:
let
  pythonPkgs = pkgs.python310Packages;
  cryptography = pythonPkgs.cryptography;
  pyOpenSSL = pythonPkgs.pyopenssl;
  nassl = with pythonPkgs;
    buildPythonPackage rec {
      pname = "nassl";
      version = "5.0.0";
      format = "wheel";
      src = builtins.fetchurl {
        # TODO make this work on other platforms: https://pypi.org/project/nassl/5.0.0/#files
        url =
          "https://files.pythonhosted.org/packages/5b/c4/1af344cedf2dff7329d4bdbba03f3512c37b7972e5119fa874fb9472ce00/nassl-5.0.0-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
        sha256 =
          "sha256:c2c4ff3d0cb1daae984dc99b6673722263b960fdf0b6aecd2d46020652e4f86f";
      };
      propagatedBuildInputs = [ pyOpenSSL ];

    };
in pkgs.python310.withPackages (ps: [
  ps.pep8
  ps.pytest
  ps.pytest-xdist
  ps.pytest-rerunfailures
  ps.typing-extensions
  ps.setuptools-rust
  ps.cryptography
])

