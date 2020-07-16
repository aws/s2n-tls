import copy
import pytest

from configuration import available_ports, PROTOCOLS
from common import ProviderOptions, Ciphers, Certificates, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


def multi_cipher_name(c):
    return ':'.join([x.name for x in c])


multi_cipher = [Ciphers.AES256_SHA, Ciphers.ECDHE_ECDSA_AES256_SHA]
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("multi_cipher", [multi_cipher], ids=multi_cipher_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", [Certificates.RSA_4096_SHA384, Certificates.ECDSA_384], ids=get_parameter_name)
def test_s2n_server_low_latency(managed_process, multi_cipher, provider, protocol, certificate):
    if provider is OpenSSL and 'openssl-1.0.2' in provider.get_version():
        pytest.skip('{} does not allow setting max fragmentation for packets'.format(provider))

    port = next(available_ports)

    random_bytes = data_bytes(65519)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=multi_cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.extra_flags=['--prefer-low-latency']
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(protocol, provider)

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("multi_cipher", [multi_cipher], ids=multi_cipher_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", [Certificates.RSA_4096_SHA384, Certificates.ECDSA_384], ids=get_parameter_name)
@pytest.mark.parametrize("frag_len", [512, 2048, 8192, 12345, 16384], ids=get_parameter_name)
def test_s2n_server_framented_data(managed_process, multi_cipher, provider, protocol, frag_len, certificate):
    if provider is OpenSSL and 'openssl-1.0.2' in provider.get_version():
        pytest.skip('{} does not allow setting max fragmentation for packets'.format(provider))

    port = next(available_ports)

    random_bytes = data_bytes(65519)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=multi_cipher,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=['-max_send_frag', str(frag_len)],
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.extra_flags = None
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(protocol, provider)

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout
