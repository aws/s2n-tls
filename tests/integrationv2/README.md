# Quick start

You must have run through the standard codebuild setup as described in the root README. This will make sure you
have all the dependencies installed correctly. The integration test dependencies are:

 * s2nc and s2nd (should be in the bin/ directory)
 * libs2n (should be in the lib/ directory)
 * openssl (based on the S2N_LIBCRYPTO env var)
 * tox

## Run all tests

The fastest way to run the integrationv2 tests is to run `make` in the integrationv2 directory.

```
ubuntu@host:tests/integrationv2/ $ make
```

This will automatically setup your PATH and LD_LIBRARY_PATH environment. It will execute `tox` to setup your
Python environment. Then all the integration tests will be collected and executed.

**Note** If you are running the dynamic record size test you will need to use `sudo`.

## Run one test

You can run the entire test suite using `sudo make`. You need to use `sudo` if you plan on running the dynamic
record tests.

If you only want to run a single test, you can set the `TOX_TEST_NAME` environment variable:

```
ubuntu@host:tests/integrationv2$ TOX_TEST_NAME=test_happy_path.py::test_s2n_server_happy_path make
```

This will setup your environment correctly, and execute the single test.

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
providers.

## s2nd / s2nc

You may have to add a flag to s2nc/s2nd to allow that feature from the command line. If at all possible
use long options, and use the same option in s2nc as s2nd. This attempts to limit the differences
between the two. If you are able to setup the option similar to how an OpenSSL derivitive works, that
will make things easier in the long run. An example of this is '-reconnect' in OpenSSL and '-r' in S2N.
Both have a hardcoded value of 5 reconnects. The point is to remove logic from the test, and make the
providers act as similar as possible.

## Control the provider from the test

To tell the provider you want to excersize some functionality you can add an option to the ProviderOptions
object, or you can pass extra_flags data. If multiple providers need to know about your option, choose
the ProviderOptions method. If your option is specific to one provider, just pass extra_flags.

For example, during session resumption we need to tell various clients and server to resume a session
multiple times. To do this we added the 'reconnect' and 'reconnects_before_exit' options to the ProviderOptions
object. But with dynamic thresholds we simply pass the '-D' argument as an extra flag to s2n.

In each provider that supports client authentication, you need to check if the flag is set, and
create a command line option for that particular provider. You can also add logic checks, e.g with
client authenticate the client must have a certificate to send. Otherwise the test will fail.
