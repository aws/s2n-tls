import copy
import os
import pytest
import time

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes, Curves
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name

def verify_hello_retry_request(server):  
    marker_found = False
    bytes_found = False 
    client_hello_count = 0
    server_hello_count = 0 
    finished_count = 0
    marker = b"cf 21 ad 74 e5 9a 61 11 be 1d"

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

        if marker in results.stdout:
            marker_found = True
        if b'client hello' in results.stdout:
            client_hello_count += 1
        if b'server hello' in results.stdout:
            server_hello_count += 1
        if b'finished' in results.stdout:
            finished_count += 1
        if server.data_to_send in results.stdout:
            bytes_found = True
        if marker_found and client_hello_count == 2 and server_hello_count == 2 and finished_count == 2 and bytes_found:
            return True

    return False

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_empty_keyshare(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(24)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        curve=curve,
        extra_flags=["-K", "none"],
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags = None

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    assert verify_hello_retry_request(server) is True

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_single_keyshare(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=["-K","secp256r1"],
        protocol=protocol)
    
    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=Curves.X25519,
        protocol=protocol,
        data_to_send=None,
        insecure=True,
        key=certificate.key,
        cert=certificate.cert)

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    assert verify_hello_retry_request(server) is True

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_multiple_keyshare(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=["-K","secp256r1:secp384r1"],
        protocol=protocol)
    
    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=Curves.X25519,
        protocol=protocol,
        data_to_send=None,
        insecure=True,
        key=certificate.key,
        cert=certificate.cert)

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    assert verify_hello_retry_request(server) is True
