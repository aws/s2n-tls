import copy
import pytest
import re

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes, Curves
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, to_bytes

S2N_DEFAULT_CURVE = Curves.X25519
S2N_HRR_MARKER = to_bytes("HELLO_RETRY_REQUEST")

# Mapping list of curve_names for hello retry requests server side test.
CURVE_NAMES = {
    "X25519": "x25519",
    "P-256": "secp256r1",
    "P-384": "secp384r1",
    "P-521": "secp521r1"
}


def test_nothing():
    """
    Sometimes the hello retry test parameters in combination with the s2n libcrypto
    results in no test cases existing. In this case, pass a nothing test to avoid
    marking the entire codebuild run as failed.
    """
    assert True


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_s2n_as_client(managed_process, cipher, provider, other_provider, curve, protocol, certificate):
    if curve == S2N_DEFAULT_CURVE:
        pytest.skip("No retry if server curve matches client curve")

    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags = None
    server_options.curve = curve

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        results.assert_success()
        assert to_bytes("Curve: {}".format(
            CURVE_NAMES[curve.name])) in results.stdout
        assert S2N_HRR_MARKER in results.stdout

    marker_part1 = b"cf 21 ad 74 e5"
    marker_part2 = b"9a 61 11 be 1d"

    for results in server.get_results():
        results.assert_success()
        assert marker_part1 in results.stdout and marker_part2 in results.stdout
        # The "test_all" s2n security policy includes draft Hybrid PQ groups that Openssl server prints as hex values
        assert re.search(b'Supported Elliptic Groups: [x0-9A-F:]*X25519:P-256:P-384', results.stdout) is not None
        assert to_bytes("Shared Elliptic groups: {}".format(
            server_options.curve)) in results.stdout
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_s2n_as_server(managed_process, cipher, provider, other_provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        curve=curve,
        extra_flags=['-msg', '-curves', 'X448:'+str(curve)],
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags = None

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # The client should connect and return without error
    for results in server.get_results():
        results.assert_success()
        assert random_bytes in results.stdout
        assert to_bytes("Curve: {}".format(
            CURVE_NAMES[curve.name])) in results.stdout
        assert random_bytes in results.stdout
        assert S2N_HRR_MARKER in results.stdout

    client_hello_count = 0
    server_hello_count = 0
    finished_count = 0
    # HRR random data Refer: https://tools.ietf.org/html/rfc8446#section-4.1.3
    marker = b"cf 21 ad 74 e5 9a 61 11 be 1d"

    for results in client.get_results():
        results.assert_success()
        assert marker in results.stdout
        client_hello_count = results.stdout.count(b'ClientHello')
        server_hello_count = results.stdout.count(b'ServerHello')
        finished_count = results.stdout.count(b'Finished')

    assert client_hello_count == 2
    assert server_hello_count == 2
    assert finished_count == 2


# Default Keyshare for TLS v1.3 is x25519
TEST_CURVES = ALL_TEST_CURVES[1:]


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("curve", TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_default_keyshare(managed_process, cipher, provider, other_provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags = None
    server_options.curve = curve

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        results.assert_success()
        assert to_bytes("Curve: {}".format(
            CURVE_NAMES[curve.name])) in results.stdout
        assert S2N_HRR_MARKER in results.stdout

    marker_part1 = b"cf 21 ad 74 e5"
    marker_part2 = b"9a 61 11 be 1d"

    for results in server.get_results():
        results.assert_success()
        assert marker_part1 in results.stdout and marker_part2 in results.stdout
        # The "test_all" s2n security policy includes draft Hybrid PQ groups that Openssl server prints as hex values
        assert re.search(b'Supported Elliptic Groups: [x0-9A-F:]*X25519:P-256:P-384', results.stdout) is not None
        assert to_bytes("Shared Elliptic groups: {}".format(
            server_options.curve)) in results.stdout
        assert random_bytes in results.stdout
