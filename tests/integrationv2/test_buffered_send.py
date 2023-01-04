import pytest

from configuration import available_ports, PROTOCOLS, ALL_TEST_CIPHERS, MINIMAL_TEST_CERTS
from common import ProviderOptions, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name, to_bytes, to_string

SEND_DATA_SIZE = 2 ** 14

# CLOSE_MARKER must a substring of SEND_DATA exactly once, and must be its suffix
CLOSE_MARKER = "unique-suffix-close-marker"

SEND_DATA = data_bytes(SEND_DATA_SIZE - len(CLOSE_MARKER)) + to_bytes(CLOSE_MARKER)
SEND_DATA_STRING = to_string(SEND_DATA)

K_BYTES = 1024
SEND_BUFFER_SIZE_MIN = 1034
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

FRAGMENT_PREFERENCE = [
    None,
    "--prefer-low-latency",
    "--prefer-throughput"
]


def test_SEND_BUFFER_SIZE_MIN_is_s2ns_min_buffer_size(managed_process):
    port = next(available_ports)

    s2n_options = ProviderOptions(mode=Provider.ServerMode,
                                  port=port,
                                  data_to_send="test",
                                  extra_flags=['--buffered-send', SEND_BUFFER_SIZE_MIN])

    s2nd = managed_process(S2N, s2n_options)

    s2n_options.mode = Provider.ClientMode
    s2n_options.extra_flags = ['--buffered-send', SEND_BUFFER_SIZE_MIN - 1]
    s2nc = managed_process(S2N, s2n_options)

    for results in s2nc.get_results():
        assert "Error setting send buffer size" in str(results.stderr)
        assert results.exit_code != 0

    for results in s2nd.get_results():
        assert results.exit_code != 0


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [GnuTLS, OpenSSL, S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("fragment_preference", FRAGMENT_PREFERENCE, ids=get_parameter_name)
def test_s2n_server_buffered_send(managed_process, cipher, provider, protocol, certificate, buffer_size,
                                  fragment_preference):
    # Communication Timeline
    # Client [S2N|OpenSSL|GnuTLS]  | Server [S2N]
    # Handshake                    | Handshake
    #                              | Send SEND_DATA (with CLOSE_MARKER)
    # Closes with CLOSE_MARKER     | Close
    port = next(available_ports)

    provider_client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=None,
        insecure=True,
        protocol=protocol,
        verbose=False)

    extra_flags = ['--buffered-send', buffer_size]
    if fragment_preference is not None:
        extra_flags.append(fragment_preference)

    s2n_server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=SEND_DATA,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert,
        extra_flags=extra_flags)

    server = managed_process(S2N, s2n_server_options, send_marker=[S2N.get_send_marker()])
    client = managed_process(provider, provider_client_options, close_marker=CLOSE_MARKER)

    for results in client.get_results():
        assert SEND_DATA_STRING in str(results.stdout)
        results.assert_success()

    for results in server.get_results():
        # the server should close without error
        # but there is otherwise nothing of interest on stdout
        results.assert_success()


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("fragment_preference", FRAGMENT_PREFERENCE, ids=get_parameter_name)
def test_s2n_client_buffered_send(managed_process, cipher, provider, protocol, certificate, buffer_size,
                                  fragment_preference):
    # Communication Timeline
    # Client [S2N]                       | Server [S2N|OpenSSL]
    # Handshake                          | Handshake
    # Send SEND_DATA (with CLOSE_MARKER) | Receive the Data Bytes
    # Close                              | Close on CLOSE_MARKER
    port = next(available_ports)

    extra_flags = ['--buffered-send', buffer_size]
    if fragment_preference is not None:
        extra_flags.append(fragment_preference)

    s2n_client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=SEND_DATA,
        insecure=True,
        protocol=protocol,
        extra_flags=extra_flags)

    provider_server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert,
        verbose=False)

    server = managed_process(provider, provider_server_options,
                             close_marker=CLOSE_MARKER)
    client = managed_process(S2N, s2n_client_options)

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        assert SEND_DATA_STRING in str(results.stdout)
        results.assert_success()
