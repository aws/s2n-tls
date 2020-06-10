import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, get_expected_openssl_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS12, Protocols.TLS11, Protocols.TLS10], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL], ids=get_parameter_name)
def test_s2nc_tls13_negotiates_tls12(managed_process, cipher, curve, protocol, provider, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(24)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=Protocols.TLS13)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.protocol = protocol

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    client_version = get_expected_s2n_version(Protocols.TLS13, provider)
    actual_version = get_expected_s2n_version(protocol, provider)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Client protocol version: {}".format(client_version).encode('utf-8')) in results.stdout
        assert bytes("Actual protocol version: {}".format(actual_version).encode('utf-8')) in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        if provider is S2N:
            # The server is only TLS12, so it reads the version from the CLIENT_HELLO, which is never above TLS12
            # This check only cares about S2N. Trying to maintain expected output of other providers doesn't
            # add benefit to whether the S2N client was able to negotiate a lower TLS version.
            assert bytes("Client protocol version: {}".format(actual_version).encode('utf-8')) in results.stdout
            assert bytes("Actual protocol version: {}".format(actual_version).encode('utf-8')) in results.stdout

        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS12, Protocols.TLS11, Protocols.TLS10], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL], ids=get_parameter_name)
def test_s2nd_tls13_negotiates_tls12(managed_process, cipher, curve, protocol, provider, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(24)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.protocol = Protocols.TLS13

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    server_version = get_expected_s2n_version(Protocols.TLS13, provider)
    actual_version = get_expected_s2n_version(protocol, provider)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        if provider is S2N:
            # The client will get the server version from the SERVER HELLO, which will be the negotiated version
            assert bytes("Server protocol version: {}".format(actual_version).encode('utf-8')) in results.stdout
            assert bytes("Actual protocol version: {}".format(actual_version).encode('utf-8')) in results.stdout
        elif provider is OpenSSL:
            # This check cares about other providers because we want to know that they did negotiate the version
            # that our S2N server intended to negotiate.
            openssl_version = get_expected_openssl_version(protocol)
            assert bytes("Protocol  : {}".format(openssl_version).encode('utf-8')) in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Server protocol version: {}".format(server_version).encode('utf-8')) in results.stdout
        assert bytes("Actual protocol version: {}".format(actual_version).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout
