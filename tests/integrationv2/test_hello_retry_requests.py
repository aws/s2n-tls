import copy
import os
import pytest
import time

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes, Curves
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name


# List of keyshares for hello retry requests client side test.
HRR_CLIENT_KEYSHARES = [
    ["-K", "none"],
    ["-K", "secp256r1"],
    ["-K", "secp256r1:secp384r1"],
]


# Mapping list of curve_names for hello retry requests server side test.
CURVE_NAMES = {
    "X25519": "x25519",
    "P-256": "secp256r1",
    "P-384": "secp384r1"
}

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("keyshare", HRR_CLIENT_KEYSHARES, ids=get_parameter_name)
def test_hrr_with_s2n_as_client(managed_process, cipher, provider, curve, protocol, certificate, keyshare):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        curve=curve,
        extra_flags=keyshare,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags = None
    server_options.curve = Curves.X25519

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Curve: {}".format("x25519").encode('utf-8')) in results.stdout

    marker_part1 = b"cf 21 ad 74 e5"
    marker_part2 = b"9a 61 11 be 1d"

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert marker_part1 in results.stdout and marker_part2 in results.stdout
        if 'none' in keyshare:
            assert b'"key share" (id=51), len=2\n0000 - 00 00' in results.stdout
        assert b'Supported Elliptic Groups: X25519:P-256:P-384' in results.stdout
        assert bytes("Shared Elliptic groups: {}".format(server_options.curve).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_s2n_as_server(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        curve=curve,
        extra_flags = ['-msg', '-curves', 'X448:'+str(curve)],
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
        assert results.exception is None
        assert results.exit_code == 0
        assert random_bytes in results.stdout
        assert bytes("Curve: {}".format(CURVE_NAMES[curve.name]).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout

    client_hello_count = 0
    server_hello_count = 0
    finished_count = 0
    # HRR random data Refer: https://tools.ietf.org/html/rfc8446#section-4.1.3
    marker = b"cf 21 ad 74 e5 9a 61 11 be 1d"

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
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
@pytest.mark.parametrize("curve", TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_default_keyshare(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
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
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Curve: {}".format(CURVE_NAMES[curve.name]).encode('utf-8')) in results.stdout

    marker_part1 = b"cf 21 ad 74 e5"
    marker_part2 = b"9a 61 11 be 1d"

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert marker_part1 in results.stdout and marker_part2 in results.stdout
        assert b'Supported Elliptic Groups: X25519:P-256:P-384' in results.stdout
        assert bytes("Shared Elliptic groups: {}".format(server_options.curve).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout

