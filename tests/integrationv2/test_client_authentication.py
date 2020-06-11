import copy
import os
import pytest
import time

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROVIDERS, PROTOCOLS
from common import Certificates, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", [cipher for cipher in ALL_TEST_CIPHERS if 'ECDSA' not in cipher.name], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_client_auth_with_s2n_server(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        use_client_auth=True,
        client_key_file=certificate.key,
        client_certificate_file=certificate.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = Certificates.RSA_2048_SHA256_WILDCARD.key
    server_options.cert = Certificates.RSA_2048_SHA256_WILDCARD.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(protocol, provider)

    # S2N should indicate the procotol version in a successful connection.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_client_auth_with_s2n_server_using_nonmatching_certs(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=b'',
        use_client_auth=True,
        client_key_file=certificate.key,
        client_certificate_file=certificate.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = Certificates.RSA_2048_SHA256_WILDCARD.key
    server_options.cert = Certificates.RSA_2048_SHA256_WILDCARD.cert

    # Tell the server to expect the wrong certificate
    server_options.client_certificate_file=Certificates.RSA_2048_SHA256_WILDCARD.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    # OpenSSL should return 1 because the connection failed
    for results in client.get_results():
        assert results.exception is None
        if protocol == Protocols.TLS13:
            # Exit code 104 is connection reset by peer
            # This is almost always 104, but we have hit an occasion where s_client
            # closed cleanly.
            assert results.exit_code == 104 or results.exit_code == 0
        else:
            assert results.exit_code == 1

    # S2N should tell us that mutual authentication failed
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 255
        assert b'Error: Mutual Auth was required, but not negotiated' in results.stderr


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_client_auth_with_s2n_client_no_cert(managed_process, cipher, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        use_client_auth=True,
        client_trust_store=Certificates.RSA_2048_SHA256_WILDCARD.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = Certificates.RSA_2048_SHA256_WILDCARD.key
    server_options.cert = Certificates.RSA_2048_SHA256_WILDCARD.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(OpenSSL, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    # Openssl should indicate the procotol version in a successful connection.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert random_bytes in results.stdout
        if protocol is Protocols.TLS13:
            message = bytes("SSL_accept:SSLv3/TLS read client certificate\nSSL_accept:SSLv3/TLS read finished".encode('utf-8'))
        else:
            message = bytes("SSL_accept:SSLv3/TLS read client certificate\nSSL_accept:SSLv3/TLS read client key exchange\nSSL_accept:SSLv3/TLS read change cipher spec\nSSL_accept:SSLv3/TLS read finished".encode('utf-8'))

        assert message in results.stderr


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_client_auth_with_s2n_client_with_cert(managed_process, cipher, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        use_client_auth=True,
        client_key_file=certificate.key,
        client_certificate_file=certificate.cert,
        client_trust_store=Certificates.RSA_2048_SHA256_WILDCARD.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = Certificates.RSA_2048_SHA256_WILDCARD.key
    server_options.cert = Certificates.RSA_2048_SHA256_WILDCARD.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(OpenSSL, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    # Openssl should indicate the procotol version in a successful connection.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert random_bytes in results.stdout

        if protocol is Protocols.TLS13:
            message = bytes("SSL_accept:SSLv3/TLS read client certificate\nSSL_accept:SSLv3/TLS read certificate verify\nSSL_accept:SSLv3/TLS read finished".encode('utf-8'))
        else:
            message = bytes('SSL_accept:SSLv3/TLS read client certificate\nSSL_accept:SSLv3/TLS read client key exchange\nSSL_accept:SSLv3/TLS read certificate verify\nSSL_accept:SSLv3/TLS read change cipher spec\nSSL_accept:SSLv3/TLS read finished'.encode('utf-8'))

        assert message in results.stderr
