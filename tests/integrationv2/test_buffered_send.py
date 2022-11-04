import pytest

from configuration import available_ports, PROTOCOLS, ALL_TEST_CIPHERS, Certificates
from common import ProviderOptions, data_bytes
from fixtures import managed_process # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name, to_bytes, is_subsequence

SEND_DATA_SIZE = 2 ** 14

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

FRAGMENT_PREFERENCE = [
    None,
    "--prefer-low-latency",
    "--prefer-throughput"
]

TEST_CERTS = [
    Certificates.RSA_2048_SHA256,
    Certificates.RSA_PSS_2048_SHA256,
    Certificates.ECDSA_256
]

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [GnuTLS, OpenSSL, S2N], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("fragment_preference", FRAGMENT_PREFERENCE, ids=get_parameter_name)
def test_s2n_buffered_send_server(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size, fragment_preference):
    # Communication Timeline
    # Client [S2N|OpenSSL|GnuTLS]  | Server [S2N]
    # Handshake                    | Handshake
    #  Handshake finish indicated
    #  by the client send marker
    # Send Server Send Marker      | Receive the Server Send Marker
    #                              | Send Data Bytes to Client
    #                                 stresses the send buffer
    #                                 center of test
    #                              | Send Client Close Marker
    # Close                        | Close

    starting_client_send_marker = other_provider.get_send_marker()

    starting_server_send_marker = "YTREWQ"
    client_inital_app_data = to_bytes(starting_server_send_marker)
    client_close_marker = server_sent_final = "QWERTY"
    data_bytes_server = data_bytes(SEND_DATA_SIZE) + to_bytes(server_sent_final)

    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        data_to_send=client_inital_app_data,
        insecure=True,
        protocol=protocol)

    extra_flags = ['--buffered-send', buffer_size]
    if fragment_preference is not None:
            extra_flags.append(fragment_preference)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=data_bytes_server,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert,
        extra_flags=extra_flags)

    server = managed_process(provider, server_options, send_marker=[starting_server_send_marker])
    client = managed_process(other_provider, client_options,
        send_marker=[starting_client_send_marker], close_marker=client_close_marker)

    for results in client.get_results():
        # for small buffer sizes the received data will not be contiguous on stdout
        assert(is_subsequence(data_bytes_server, results.stdout))
        results.assert_success()

    for results in server.get_results():
        # the server should close without error
        # but there is otherwise nothing of interest on stdout 
        results.assert_success()


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("buffer_size", SEND_BUFFER_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("fragment_preference", FRAGMENT_PREFERENCE, ids=get_parameter_name)
def test_s2n_buffered_send_client(managed_process, cipher, other_provider, provider, protocol, certificate, buffer_size, fragment_preference):
    # Communication Timeline
    # Client [S2N]                 | Server [S2N|OpenSSL]
    # Handshake                    | Handshake
    #  Handshake finish indicated
    # Send Data Bytes to Server    | Receive the Data Bytes
    #  stresses the send buffer
    #  center of test
    # Send Server Close Marker     | Receive the close Marker
    # Close                        | Close
    port = next(available_ports)

    server_close_marker = client_sent_final = "QWERTY"
    client_data_to_send = data_bytes(SEND_DATA_SIZE) + to_bytes(client_sent_final)

    extra_flags = ['--buffered-send', buffer_size]
    if fragment_preference is not None:
        extra_flags.append(fragment_preference)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        data_to_send=client_data_to_send,
        insecure=True,
        protocol=protocol,
        extra_flags=extra_flags)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert)

    server = managed_process(provider, server_options, close_marker=server_close_marker)
    client = managed_process(other_provider, client_options, send_marker=[other_provider.get_send_marker()])

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        assert(is_subsequence(client_data_to_send, results.stdout))
        results.assert_success()
