import copy
import pytest

from configuration import available_ports, PROTOCOLS, ALL_TEST_CIPHERS, ALL_TEST_CERTS
from common import ProviderOptions, Ciphers, Certificates, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes

SEND_BUFFER_SIZE = 2 ** 16

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("client_provider", [OpenSSL, GnuTLS, S2N], ids=get_parameter_name)
@pytest.mark.parametrize("server_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", [ 2 ** y for y in range(15, 20, 2)] , ids=get_parameter_name) # Test various buffer sizes until the buffer size is larger than SEND_BUFFER_SIZE
def test_s2n_buffered_send(managed_process, cipher, client_provider, server_provider, protocol, certificate, buffer_size):
    port = next(available_ports)

    random_bytes = data_bytes(SEND_BUFFER_SIZE)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    if client_provider is S2N:
        client_options.extra_flags = ['--buffered-send', buffer_size]

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.extra_flags = ['--buffered-send', buffer_size]
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.cipher = None

    server = managed_process(server_provider, server_options, timeout=5)
    client = managed_process(client_provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()
        assert random_bytes in results.stdout
