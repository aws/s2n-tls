import pytest

from configuration import available_ports, PROTOCOLS, Protocols, ALL_TEST_CIPHERS, TLS13_CIPHERS, Certificates
from common import ProviderOptions, data_bytes
from fixtures import managed_process # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name, to_bytes

SEND_DATA_SIZE = 2 ** 16

K_BYTES = 1024 
SEND_BUFFER_SIZE_MIN = 1031
SEND_BUFFER_SIZE_MIN_RECOMMENDED = 2 * K_BYTES
SEND_BUFFER_SIZE_MULTI_RECORD = 17 * K_BYTES
SEND_BUFFER_SIZE_PREFER_THROUGHPUT = 35 * K_BYTES
SEND_BUFFER_SIZE_HUGE = 512 * K_BYTES

SEND_BUFFER_SIZES = [
    SEND_BUFFER_SIZE_MIN,
    SEND_BUFFER_SIZE_MIN_RECOMMENDED,
    SEND_BUFFER_SIZE_MULTI_RECORD,
    SEND_BUFFER_SIZE_PREFER_THROUGHPUT,
    SEND_BUFFER_SIZE_HUGE
]

TEST_CERTS = [
    Certificates.RSA_4096_SHA512,
    Certificates.ECDSA_384,
    Certificates.RSA_PSS_2048_SHA256
]

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N, OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("fragment_preference", [None, "--prefer-low-latency", "--prefer-throughput"], ids=get_parameter_name)
def test_s2n_buffered_send_server(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size, fragment_preference):
    port = next(available_ports)
    random_bytes = data_bytes(SEND_DATA_SIZE)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=None,
        insecure=True,
        protocol=protocol)

    extra_flags = ['--buffered-send', buffer_size] + \
        ([] if fragment_preference is None else [fragment_preference])

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert,
        extra_flags=extra_flags)

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(other_provider, client_options, timeout=5)

    for results in client.get_results():
        if other_provider is S2N:
            assert(len(results.stderr) == 0)
            assert(to_bytes("CONNECTED") in results.stdout)
        results.assert_success()

    for results in server.get_results():
        results.assert_success()


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name) # PROTOCOLS """
@pytest.mark.parametrize("certificate", TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
def test_s2n_buffered_send_client(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size):
    port = next(available_ports)
    random_bytes = data_bytes(SEND_DATA_SIZE)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=None,
        insecure=True,
        protocol=protocol,
        extra_flags=['--buffered-send', buffer_size])

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert)

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(other_provider, client_options, timeout=5)

    for results in client.get_results():
        assert(len(results.stderr) == 0)
        assert(to_bytes("CONNECTED") in results.stdout)
        results.assert_success()

    for results in server.get_results():
        results.assert_success()

