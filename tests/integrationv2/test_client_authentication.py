import copy
import pytest

from configuration import (available_ports, ALL_TEST_CIPHERS, PROTOCOLS)
from common import Certificates, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes


# If we test every available cert, the test takes too long.
# Choose a good representative subset.
CERTS_TO_TEST = [
    Certificates.RSA_1024_SHA256,
    Certificates.RSA_4096_SHA512,
    Certificates.ECDSA_256,
    Certificates.ECDSA_384,
    Certificates.RSA_PSS_2048_SHA256,
]


def assert_openssl_handshake_complete(results, is_complete=True):
    if is_complete:
        assert b'read finished' in results.stderr
        assert b'write finished' in results.stderr
    else:
        assert b'read finished' not in results.stderr or b'write finished' not in results.stderr


def assert_s2n_handshake_complete(results, protocol, provider, is_complete=True):
    expected_version = get_expected_s2n_version(protocol, provider)
    if is_complete:
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in results.stdout
    else:
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) not in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("client_certificate", CERTS_TO_TEST, ids=get_parameter_name)
def test_client_auth_with_s2n_server(managed_process, provider, other_provider, protocol, cipher, certificate,
                                     client_certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        use_client_auth=True,
        key=client_certificate.key,
        cert=client_certificate.cert,
        trust_store=certificate.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.trust_store = client_certificate.cert

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # Openssl should send a client certificate and complete the handshake
    for results in client.get_results():
        results.assert_success()
        assert b'write client certificate' in results.stderr
        assert b'write certificate verify' in results.stderr
        assert_openssl_handshake_complete(results)

    # S2N should successfully connect
    for results in server.get_results():
        results.assert_success()
        assert_s2n_handshake_complete(results, protocol, provider)
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("client_certificate", CERTS_TO_TEST, ids=get_parameter_name)
def test_client_auth_with_s2n_server_using_nonmatching_certs(managed_process, provider, other_provider, protocol,
                                                             cipher, certificate, client_certificate):
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=b'',
        use_client_auth=True,
        key=client_certificate.key,
        cert=client_certificate.cert,
        trust_store=certificate.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    # Tell the server to expect the wrong certificate
    server_options.trust_store = Certificates.RSA_2048_SHA256_WILDCARD.cert

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    # Openssl should tell us that a certificate was sent, but the handshake did not complete
    for results in client.get_results():
        assert results.exception is None
        assert b'write client certificate' in results.stderr
        assert b'write certificate verify' in results.stderr
        # TLS1.3 OpenSSL fails after the handshake, but pre-TLS1.3 fails during
        if protocol is not Protocols.TLS13:
            assert results.exit_code != 0
            assert_openssl_handshake_complete(results, False)

    # S2N should tell us that mutual authentication failed due to an untrusted cert
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code != 0
        assert b'Certificate is untrusted' in results.stderr
        assert b'Error: Mutual Auth was required, but not negotiated' in results.stderr
        assert_s2n_handshake_complete(results, protocol, provider, False)


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTS_TO_TEST, ids=get_parameter_name)
def test_client_auth_with_s2n_client_no_cert(managed_process, provider, other_provider, protocol, cipher, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        use_client_auth=True,
        trust_store=certificate.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # Openssl should tell us that a cert was requested but not received
    for results in server.get_results():
        results.assert_success()
        assert b'write certificate request' in results.stderr
        assert b'read client certificate' not in results.stderr
        assert b"peer did not return a certificate" in results.stderr
        assert_openssl_handshake_complete(results, False)

    for results in client.get_results():
        assert results.exception is None
        # TLS1.3 OpenSSL fails after the handshake, but pre-TLS1.3 fails during
        if protocol is not Protocols.TLS13:
            assert (results.exit_code != 0)
            assert b"Failed to negotiate: 'TLS alert received'" in results.stderr
            assert_s2n_handshake_complete(results, protocol, provider, False)


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("client_certificate", CERTS_TO_TEST, ids=get_parameter_name)
def test_client_auth_with_s2n_client_with_cert(managed_process, provider, other_provider, protocol, cipher, certificate,
                                               client_certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        use_client_auth=True,
        key=client_certificate.key,
        cert=client_certificate.cert,
        trust_store=certificate.cert,
        insecure=False,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.trust_store = client_certificate.cert

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        results.assert_success()
        assert_s2n_handshake_complete(results, protocol, provider)

    # Openssl should indicate the certificate was successfully received.
    for results in server.get_results():
        results.assert_success()
        assert random_bytes[1:] in results.stdout
        assert b'read client certificate' in results.stderr
        assert b'read certificate verify' in results.stderr
        assert_openssl_handshake_complete(results)
