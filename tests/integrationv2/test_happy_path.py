import copy
import os
import pytest
import time

from configuration import available_ports, CIPHERSUITES, CURVES, PROVIDERS
from common import ProviderOptions, data_bytes
from fixtures import managed_process
from providers import S2N


@pytest.mark.parametrize("cipher", CIPHERSUITES)
@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("provider", PROVIDERS)
def test_s2n_server_happy_path(managed_process, cipher, curve, provider):
    host = "localhost"
    port = next(available_ports)

    # s2nd can receive large amounts of data because all the data is
    # echo'd to stdout unmodified. This lets us compare received to
    # expected easily.
    # The downside here is that, should the test fail, all 4 mbs will
    # be dumped in the exception.
    random_bytes = data_bytes(4194304)
    client_options = ProviderOptions(
        mode="client",
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        tls13=True)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
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
        assert random_bytes in results.stdout


@pytest.mark.parametrize("cipher", CIPHERSUITES)
@pytest.mark.parametrize("curve", CURVES)
@pytest.mark.parametrize("provider", PROVIDERS)
def test_s2n_client_happy_path(managed_process, cipher, curve, provider):
    host = "localhost"
    port = next(available_ports)

    # We can only send 4096 bytes here because of the way some servers chunk
    # output (when writing to stdout). If we send 8192 bytes, then openssl
    # will print some debugging information in the middle of our chunk.
    # We still want that debugging data in case of a failure, so we just
    # send less data, rather than lose debug information.
    random_bytes = data_bytes(4096)
    client_options = ProviderOptions(
        mode="client",
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        tls13=True)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
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
        assert random_bytes in results.stdout
