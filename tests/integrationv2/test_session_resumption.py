import copy
import os
import pytest
import time

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS
from common import ProviderOptions, Protocols
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [p for p in PROTOCOLS if p != Protocols.TLS13], ids=get_parameter_name)
def test_session_resumption_s2n_server(managed_process, cipher, curve, protocol, certificate):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.reconnects_before_exit = 6
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(bytes("Session-ID:".encode('utf-8'))) == 6

    expected_version = get_expected_s2n_version(protocol, OpenSSL)

    # S2N should indicate the procotol version in a successful connection.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(bytes("Actual protocol version: {}".format(expected_version).encode('utf-8'))) == 6
