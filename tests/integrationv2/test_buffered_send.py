import pytest

from configuration import available_ports, PROTOCOLS, ALL_TEST_CIPHERS, Certificates
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

def is_subsequence(s, t):
    """predicate: is s a subsequence of t?

    Parameters
    ----------
    s: bytes
        subsequence to look for
    t: str, bytes
        sequence to look in

    Returns
    -------
    bool
        True if s is a subsequence, False if not 
    """
    s = str(s)[2:-1] # Remove the b' and ' from the converted bytes
    t = str(t)
    s_len, t_len = len(s), len(t)
    s_index, t_index = 0, 0
    while (s_index < s_len and t_index < t_len):
        if (s[s_index] == t[t_index]):
            s_index += 1
        t_index += 1
    return s_index == s_len


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
    # Send Server Send Marker      | Receive the Server Send Marker "SENT_FROM_CLIENT"
    #                              | Send Data Bytes to Client (stresses the send buffer - center of test)
    #                              | Send Client Close Marker "SENT_FROM_SERVER"
    # Close                        | Close
    
    # for the corresponding provider, these strings appear when on stdout when the handshake is finished
    starting_client_send_markers = {
        GnuTLS: "Handshake was completed",
        OpenSSL: "write to",
        S2N: "ready"
    }
    starting_client_send_marker = starting_client_send_markers[other_provider]

    starting_server_send_marker = "SENT_FROM_CLIENT"
    client_inital_app_data = to_bytes(starting_server_send_marker)
    client_close_marker = server_sent_final = "SENT_FROM_SERVER"
    data_bytes_server = data_bytes(SEND_DATA_SIZE) + to_bytes(server_sent_final)

    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        data_to_send=client_inital_app_data,
        insecure=True,
        protocol=protocol)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        data_to_send=data_bytes_server,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert,
        extra_flags=['--buffered-send', buffer_size] +
            ([] if fragment_preference is None else [fragment_preference]))

    server = managed_process(provider, server_options, timeout=30, send_marker=[starting_server_send_marker])
    client = managed_process(other_provider, client_options, timeout=30,
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
    #  "s2n is ready"
    # Send Data Bytes to Server    | Receive the Data Bytes
    #  stresses the send buffer
    #  center of test
    # Send Server Close Marker     | Receive the close Marker
    # Close                        | Close
    port = next(available_ports)
    server_close_marker = client_sent_final = "SENT_FROM_CLIENT"
    client_data_to_send = data_bytes(SEND_DATA_SIZE) + to_bytes(client_sent_final)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        data_to_send=client_data_to_send,
        insecure=True,
        protocol=protocol,
        extra_flags=['--buffered-send', buffer_size] +
            ([] if fragment_preference is None else [fragment_preference]))

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        insecure=True,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert)

    server = managed_process(provider, server_options, close_marker=server_close_marker, timeout=30)
    client = managed_process(other_provider, client_options, send_marker=["s2n is ready"], timeout=30)

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        assert(is_subsequence(client_data_to_send, results.stdout))
        results.assert_success()
