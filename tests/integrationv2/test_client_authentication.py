import copy
import os
import pytest
import time

from configuration import available_ports, CIPHERSUITES, CURVES, PROVIDERS
from common import ProviderOptions, data_bytes
from fixtures import managed_process
from providers import S2N, OpenSSL


@pytest.mark.parametrize("cipher", CIPHERSUITES)
@pytest.mark.parametrize("curve", CURVES)
def test_client_auth_with_s2n_server(managed_process, cipher, curve):
    host = "localhost"
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode="client",
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        use_client_auth=True,
        client_key_file='../pems/rsa_1024_sha256_client_key.pem',
        client_certificate_file='../pems/rsa_1024_sha256_client_cert.pem',
        insecure=False,
        tls13=False)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = "server"
    server_options.key = "../pems/rsa_2048_sha256_wildcard_key.pem"
    server_options.cert = "../pems/rsa_2048_sha256_wildcard_cert.pem"

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    # S2N should indicate the procotol version in a successful connection.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b"Actual protocol version: 33" in results.stdout
        assert random_bytes in results.stdout


@pytest.mark.parametrize("cipher", CIPHERSUITES)
@pytest.mark.parametrize("curve", CURVES)
def test_client_auth_with_s2n_server_using_nonmatching_certs(managed_process, cipher, curve):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode="client",
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=b'',
        use_client_auth=True,
        client_key_file='../pems/rsa_1024_sha256_client_key.pem',
        client_certificate_file='../pems/rsa_1024_sha256_client_cert.pem',
        insecure=False,
        tls13=False)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = "server"
    server_options.key = "../pems/rsa_2048_sha256_wildcard_key.pem"
    server_options.cert = "../pems/rsa_2048_sha256_wildcard_cert.pem"
    # Tell the server to expect the wrong certificate
    server_options.client_certificate_file='../pems/rsa_2048_sha256_client_cert.pem'

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    # OpenSSL should return 1 because the connection failed
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 1

    # S2N should tell us that mutual authentication failed
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 255
        assert b'Error: Mutual Auth was required, but not negotiated' in results.stderr