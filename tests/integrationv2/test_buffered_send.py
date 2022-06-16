import pytest

from configuration import available_ports, PROTOCOLS, Protocols, ALL_TEST_CIPHERS, TLS13_CIPHERS, ALL_TEST_CERTS
from common import ProviderOptions, data_bytes
from fixtures import managed_process # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name

SEND_DATA_SIZE = 2 ** 16

K_BYTES = 1024 
SEND_BUFFER_SIZE_MIN = 1031
SEND_BUFFER_SIZE_MIN_RECOMMENDED = 2 * K_BYTES
SEND_BUFFER_SIZE_MULTI_RECORD = 17 * K_BYTES
SEND_BUFFER_SIZE_PREFER_THROUGHPUT = 35 * K_BYTES
SEND_BUFFER_SIZE_HUGE = 512 * K_BYTES

SEND_BUFFER_SIZES = [
    SEND_BUFFER_SIZE_MIN_RECOMMENDED,
    SEND_BUFFER_SIZE_MULTI_RECORD,
    SEND_BUFFER_SIZE_PREFER_THROUGHPUT,
]

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N, OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", [SEND_BUFFER_SIZE_HUGE, SEND_BUFFER_SIZE_MIN], ids=get_parameter_name)
@pytest.mark.parametrize("fragment_pref", [None, "--prefer-low-latency", "--prefer-throughput"], ids=get_parameter_name) # Test various fragment prefrences
def test_s2n_buffered_send_all_settings_server(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size, fragment_pref):
    port = next(available_ports)

    random_bytes = data_bytes(SEND_DATA_SIZE)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    if other_provider is S2N:
        client_options.extra_flags = ['--buffered-send', buffer_size]

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=None,
        insecure=True,
        protocol=protocol)
 
    server_options.extra_flags = ['--buffered-send', buffer_size]
    if fragment_pref is not None:
        server_options.extra_flags.append(fragment_pref)

    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.cipher = None

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(other_provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()
        if provider is S2N: random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N, OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("fragment_pref", [None, "--prefer-low-latency", "--prefer-throughput"], ids=get_parameter_name) # Test various fragment prefrences
def test_s2n_buffered_send_all_sizes_server(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size, fragment_pref):
    port = next(available_ports)

    random_bytes = data_bytes(SEND_DATA_SIZE)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    if other_provider is S2N:
        client_options.extra_flags = ['--buffered-send', buffer_size]

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=None,
        insecure=True,
        protocol=protocol)
 
    server_options.extra_flags = ['--buffered-send', buffer_size]
    if fragment_pref is not None:
        server_options.extra_flags.append(fragment_pref)

    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.cipher = None

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(other_provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()
        if provider is S2N: random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", [SEND_BUFFER_SIZE_HUGE, SEND_BUFFER_SIZE_MIN], ids=get_parameter_name)
@pytest.mark.parametrize("fragment_pref", [None, "--prefer-low-latency", "--prefer-throughput"], ids=get_parameter_name)
def test_s2n_buffered_send_all_settings_client(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size, fragment_pref):
    port = next(available_ports)

    random_bytes = data_bytes(SEND_DATA_SIZE)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    client_options.extra_flags = ['--buffered-send', buffer_size]

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=None,
        insecure=True,
        protocol=protocol)

    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.cipher = None

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(other_provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("fragment_pref", [None, "--prefer-low-latency", "--prefer-throughput"], ids=get_parameter_name)
def test_s2n_buffered_send_all_settings_client(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size, fragment_pref):
    port = next(available_ports)

    random_bytes = data_bytes(SEND_DATA_SIZE)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    client_options.extra_flags = ['--buffered-send', buffer_size]

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=None,
        insecure=True,
        protocol=protocol)

    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.cipher = None

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(other_provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()

