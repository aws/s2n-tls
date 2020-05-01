import copy
import os
import pytest
import time

from configuration import available_ports, CIPHERSUITES, CURVES, PROVIDERS
from common import ProviderOptions
from fixtures import managed_process
from providers import S2N


@pytest.mark.parametrize("cipher", CIPHERSUITES)
@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("provider", PROVIDERS)
def test_s2n_server_happy_path(managed_process, cipher, curve, provider):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode="client",
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        tls13=True)

    server_options = copy.copy(client_options)
    server_options.mode = "server"
    server_options.key = "../pems/ecdsa_p384_pkcs1_key.pem"
    server_options.cert = "../pems/ecdsa_p384_pkcs1_cert.pem"

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # The client will be one of all supported providers. We
    # just want to make sure there was no exception and that
    # the client exited cleanly.
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    # The server is always S2N in this test, so we can examine
    # the stdout reliably.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b"Actual protocol version: 34" in results.stdout


@pytest.mark.parametrize("cipher", CIPHERSUITES)
@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("provider", PROVIDERS)
def test_s2n_client_happy_path(managed_process, cipher, curve, provider):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode="client",
        host="localhost",
        port=port,
        cipher=cipher,
        insecure=True,
        tls13=True)

    server_options = copy.copy(client_options)
    server_options.mode = "server"
    server_options.key = "../pems/ecdsa_p384_pkcs1_key.pem"
    server_options.cert = "../pems/ecdsa_p384_pkcs1_cert.pem"

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client is always S2N in this test, so we can examine
    # the stdout reliably.
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b"Actual protocol version: 34" in results.stdout

    # The server will be one of all supported providers. We
    # just want to make sure there was no exception and that
    # the client exited cleanly.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
