import copy
import pytest

from configuration import available_ports, PROTOCOLS
from common import ProviderOptions, Ciphers, Certificates, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes


CIPHERS_TO_TEST = [
    Ciphers.AES256_SHA,
    Ciphers.ECDHE_ECDSA_AES256_SHA,
    Ciphers.AES256_GCM_SHA384
]

CERTIFICATES_TO_TEST = [
    Certificates.RSA_4096_SHA384,
    Certificates.ECDSA_384
]


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", CIPHERS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTIFICATES_TO_TEST, ids=get_parameter_name)
def test_s2n_server_low_latency(managed_process, cipher, provider, other_provider, protocol, certificate):
    if provider is OpenSSL and 'openssl-1.0.2' in provider.get_version():
        pytest.skip(
            '{} does not allow setting max fragmentation for packets'.format(provider))

    port = next(available_ports)

    random_bytes = data_bytes(65519)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.extra_flags = ['--prefer-low-latency']
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.cipher = None

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()

    expected_version = get_expected_s2n_version(protocol, provider)

    for results in server.get_results():
        results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in results.stdout
        assert random_bytes in results.stdout


def invalid_test_parameters_frag_len(*args, **kwargs):
    provider = kwargs.get("provider")
    frag_len = kwargs.get("frag_len")

    # Check to make sure frag_len is compatible with gnutls.
    if provider == GnuTLS:
        if frag_len > 4096:
            return True

    return invalid_test_parameters(*args, **kwargs)


@pytest.mark.uncollect_if(func=invalid_test_parameters_frag_len)
@pytest.mark.parametrize("cipher", CIPHERS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTIFICATES_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("frag_len", [512, 2048, 8192, 12345, 16384], ids=get_parameter_name)
def test_s2n_server_framented_data(managed_process, cipher, provider, other_provider, protocol, certificate,
                                   frag_len):
    if provider is OpenSSL and 'openssl-1.0.2' in provider.get_version():
        pytest.skip(
            '{} does not allow setting max fragmentation for packets'.format(provider))

    port = next(available_ports)

    random_bytes = data_bytes(65519)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        record_size=frag_len,
        protocol=protocol
    )

    server_options = copy.copy(client_options)
    server_options.extra_flags = None
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.cipher = None

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    for client_results in client.get_results():
        client_results.assert_success()

    expected_version = get_expected_s2n_version(protocol, provider)

    for server_results in server.get_results():
        server_results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in server_results.stdout

        if provider == GnuTLS:
            # GnuTLS ignores data sent through stdin past frag_len up to the application data
            # packet length of 4096. so, just check to make sure data up to frag_len was received.
            assert random_bytes[:frag_len] in server_results.stdout
        else:
            assert random_bytes in server_results.stdout
