# Quick start

You need to install Tox to help setup your environment. Once tox is installed, run it to setup your
local environment. Also set your path to access the tox artifacts.

```
$ tox
py38 create: /home/ubuntu/development/s2n/tests/integrationv2/.tox/py38
py38 installdeps: pep8, pytest==5.3.5, pytest-xdist
py38 installed: apipkg==1.5,attrs==19.3.0,execnet==1.7.1,importlib-metadata==1.6.0,more-itertools==8.2.0,packaging==20.3,pep8==1.7.1,pkg-resources==0.0.0,pluggy==0.13.1,py==1.8.1,pyparsing==2.4.7,pytest==5.3.5,pytest-forked==1.1.3,pytest-xdist==1.32.0,six==1.14.0,wcwidth==0.1.9,zipp==3.1.0

$ export PATH=.tox/py38/bin:$PATH
```

You can run the entire test suite using `sudo make`. You need to use `sudo` if you plan on running the dynamic
record tests.

If you don't want to run everything, you can run individual tests like this:

```
$ pytest -rpfsq test_happy_path.py::test_s2n_server_happy_path
```

# A toy example

The happy path test combines thousands of parameters, and has to validate that the
combinations match. Below is a simple test that demonstrates how lists of parameters
are combined to test all possible parameter combinations.

```python
import copy
import pytest

from configuration import available_ports, ALL_CERTS
from common import ProviderOptions, Cert, Ciphers, Protocols
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import get_parameter_name, get_expected_s2n_version


"""
Pytest will generate 8 configuration based on the parameterize options below. The
test will be run with each of the possible configurations.
"""

@pytest.mark.parametrize("cipher",
    [Ciphers.AES128_GCM_SHA256, Ciphers.CHACHA20_POLY1305_SHA256], ids=get_parameter_name)
@pytest.mark.parametrize("provider",
    [S2N, OpenSSL])
@pytest.mark.parametrize("protocol",
    [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate",
    [Cert("ECDSA_256", "ecdsa_p256_pkcs1"), Cert("ECDSA_384", "ecdsa_p384_pkcs1")], ids=get_parameter_name)
def test_example(managed_process, cipher, provider, protocol, certificate):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    expected_version = get_expected_s2n_version(protocol, provider)

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

```


# Testing a new feature

If you are testing a new feature you need to determine how to use that feature with all supported
providers. You may have to add a flag to s2nc/s2nd to allow that feature from the command line.

Next, add a flag to the ProviderOptions object. For example, add a `require_client_auth` flag
which will be a boolean. In the toy example above, you can set `require_client_auth` in the `client_options`
and `server_options`.

In each provider that supports client authentication, you need to check if the flag is set, and
create a command line option for that particular provider. You can also add logic checks, e.g with
client authenticate the client must have a certificate to send. Otherwise the test will fail.
