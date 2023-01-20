{ pkgs }:
let pythonPkgs = pkgs.python39Packages;
    cryptography = pythonPkgs.cryptography;
    # TODO: move to should we Python 3.10? Not broken there.
    # This package is marked at broken on stdenv.isDarwin && stdenv.isAarch64 see https://github.com/pyca/pyopenssl/issues/873
    pyOpenSSL = pythonPkgs.pyopenssl; 
    nassl = with pythonPkgs; buildPythonPackage rec {
      pname = "nassl";
      version = "5.0.0";
      format = "wheel";
      src = builtins.fetchurl {
        # TODO make this work on other platforms: https://pypi.org/project/nassl/5.0.0/#files
        url = "https://files.pythonhosted.org/packages/b2/5b/74deb03184dbd2500a94d6d50c95e48db566653a1c2d5203af7c468bed48/nassl-5.0.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
        sha256 = "sha256:02m9p7hq5895674drjn0c98yzlf8lr5yilhg12pzws77720z2a9n";
      };
      propagatedBuildInputs = [
        pyOpenSSL
      ];

    };
    sslyze = with pythonPkgs; buildPythonPackage rec {
      pname = "sslyze";
      version = "5.1.1";
      src = fetchPypi {
        inherit pname version;
        sha256 = "sha256-F+3wMSGQSyi+THWTjbGS33Bua+G6FyuHQRNZIc/WYeU=";
      };
      propagatedBuildInputs = [
        nassl # >=4.0.1,<5.0.0 TODO: check if this version is correct/if it matters
        cryptography # >=2.6,<37.0.0 TODO: check if this version is correct/if it matters
        tls-parser # >=2.0.0,<3.0.0 TODO: check if this version is correct/if it matters
        pydantic # >=1.7,<1.9 TODO: check if this version is correct/if it matters
      ];
    };
    in
pkgs.python39.withPackages(ps: [
  ps.pep8
  ps.pytest # ==5.3.5 TODO: check if this version is correct/if it matters
  ps.pytest-xdist # ==1.34.0 TODO: check if this version is correct/if it matters
  sslyze # ==5.0.2 TODO: check if this version is correct/if it matters
  ps.pytest-rerunfailures
  ps.tox
  ps.typing-extensions
  ps.setuptools-rust
  ps.cryptography
#  ps.pyopenssl
  nassl
])
