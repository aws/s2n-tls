import copy
import pytest

from configuration import available_ports, MULTI_CERT_TEST_CASES, PROVIDERS, PROTOCOLS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


def filter_cipher_list(*args, **kwargs):
    """
    The framework normally filters out ciphers that are not supported by the chosen
    protocol. That doesn't happen in this test because of the unique way ciphers are
    grouped for the multi certificate tests.

    This function handles that unique grouping.
    """
    protocol = kwargs.get('protocol')
    cert_test_case = kwargs.get('cert_test_case')

    lowest_protocol_cipher = min(cert_test_case.client_ciphers, key=lambda x: x.min_version)
    if protocol < lowest_protocol_cipher.min_version:
        return True

    return invalid_test_parameters(*args, **kwargs)


@pytest.mark.uncollect_if(func=filter_cipher_list)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12], ids=get_parameter_name)
@pytest.mark.parametrize("cert_test_case", MULTI_CERT_TEST_CASES)
def test_sni_match(managed_process, provider, protocol, cert_test_case):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        insecure=False,
        verify_hostname=True,
        server_name=cert_test_case.client_sni,
        cipher = cert_test_case.client_ciphers,
        protocol=protocol)

    server_options = ProviderOptions(
        mode = Provider.ServerMode,
        host=host,
        port=port,
        extra_flags=[],
        protocol=protocol)

    # Setup the certificate chain for S2ND based on the multicert test case
    cert_key_list = [(cert[0],cert[1]) for cert in cert_test_case.server_certs]
    for cert_key_path in cert_key_list:
        server_options.extra_flags.extend(['--cert', cert_key_path[0]])
        server_options.extra_flags.extend(['--key', cert_key_path[1]])

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
        if cert_test_case.client_sni is not None:
            assert bytes("Server name: {}".format(cert_test_case.client_sni).encode('utf-8')) in results.stdout

