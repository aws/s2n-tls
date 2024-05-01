import os
import shutil
import subprocess
import pytest


ALL_LCS = ["openssl-3.0", "openssl-1.1.1",
           "openssl-1.0.2", "libressl", "aws-lc"]


def translate_lc(lc: str):
    # awslc for S2N_LIBCRYPTO is special.
    if "awslc" in lc:
        return "aws-lc"
    else:
        return lc


@pytest.mark.parametrize("lc", [os.getenv("S2N_LIBCRYPTO")])
def test_s2n_libcrypto(lc):
    # Validate S2N_LIBCRYPTO is in the CMAKE_INCLUDE_PATH
    assert lc is not None
    libcrypto = translate_lc(lc)
    include_path = os.getenv("CMAKE_INCLUDE_PATH")
    assert include_path is not None
    assert libcrypto in ALL_LCS
    assert libcrypto in include_path


@pytest.mark.parametrize("lc", [os.getenv("S2N_LIBCRYPTO")])
def test_s2n_libcrypto_uniq(lc):
    # Make certain we only have the preferred libcrypto in CMAKE_INCLUDE_PATH.
    assert lc is not None
    libcrypto = translate_lc(lc)
    include_path = os.getenv("CMAKE_INCLUDE_PATH")
    assert include_path is not None
    negative_lc = ALL_LCS
    negative_lc.remove(libcrypto)
    for library in negative_lc:
        assert library not in include_path


@pytest.mark.parametrize("cmd,expected,version", [
    ("gnutls-serv", "gnutls-serv 3.7", "--version"),
    ("gnutls-cli", "gnutls-cli 3.7", "--version"),
    ("openssl", "OpenSSL 1.1.1", "version"),
    ("java", "Corretto-17", "--version")])
def test_utility_versions(cmd, expected, version):
    # Valildate utility is in the path and the correct version.
    abspath = shutil.which(cmd)
    result = ""
    with subprocess.Popen([abspath, version], shell=False, stdout=subprocess.PIPE) as p:
        output = p.stdout.readlines()
        for line in output:
            result += line.decode().strip()
        ' '.join(result)
        assert expected in result


def test_python():
    # Validate python _from nix_ is in the PATH.
    assert 'nix' in shutil.which('python')


def test_pytest():
    # Validate pytest _from nix_ is in the PATH.
    assert 'nix' in shutil.which('pytest')

if __name__ == "__main__":
    print("Use pytest")
