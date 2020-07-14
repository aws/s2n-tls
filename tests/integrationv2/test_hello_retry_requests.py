import copy
import os
import pytest
import time

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes, Curves
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name

def get_curve_name(curve):
    if curve.name == "X25519":
       return "x25519"
    elif curve.name == "P-256":
        return "secp256r1"
    elif curve.name == "P-384":
        return "secp384r1"
    else:
       return None
   
def verify_hello_retry_request_client(curve_name, client):
    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        if bytes("Curve: {}".format(curve_name).encode('utf-8')) in results.stdout:
            return True 
    return False 

def verify_hello_retry_request_server(random_bytes, curve, server):
    marker_found = False
    supported_groups_found = False
    shared_group_found = False  
    data_to_send_found = False 
    marker_part1 = b"cf 21 ad 74 e5"
    marker_part2 = b"9a 61 11 be 1d"

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

        if marker_part1 in results.stdout and marker_part2 in results.stdout:
           marker_found = True
        if b'Supported Elliptic Groups: X25519:P-256:P-384' in results.stdout:
            supported_groups_found = True 
        if bytes("Shared Elliptic groups: {}".format(curve).encode('utf-8')) in results.stdout:
            shared_group_found = True 
        if random_bytes in results.stdout:
            data_to_send_found = True 
        if marker_found and supported_groups_found and shared_group_found and data_to_send_found:
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

    random_bytes = data_bytes(64)
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

    curve_name = get_curve_name(curve)
    assert verify_hello_retry_request_client(curve_name, client) is True 
    assert verify_hello_retry_request_server(random_bytes, curve, server) is True 
 
    for results in server.get_results():
        assert b'"key share" (id=51), len=2\n0000 - 00 00' in results.stdout

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_with_single_and_multiple_keyshares(managed_process, cipher, provider, protocol, certificate):
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

    assert verify_hello_retry_request_client("x25519", client) is True 
    assert verify_hello_retry_request_server(random_bytes, Curves.X25519, server) is True 

    client_options.extra_flags = ["-K","secp256r1:secp384r1"]

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    assert verify_hello_retry_request_client("x25519", client) is True 
    assert verify_hello_retry_request_server(random_bytes, Curves.X25519, server) is True
