import copy
import platform
import pytest
import random

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, MINIMAL_TEST_CERTS, PROTOCOLS
from common import ProviderOptions, Protocols
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name


# TLS1.3 does not support renegotiation
TEST_PROTOCOLS = [x for x in PROTOCOLS if x.value < Protocols.TLS13.value]


# Command line options to enable renegotiation
S2N_RENEG_OPTION = "--renegotiation"
S2N_RENEG_ACCEPT = "accept"
S2N_RENEG_REJECT = "reject"
S2N_RENEG_WAIT = "wait"
OPENSSL_RENEG_CTRL_CMD = 'r\n'


# Output indicating renegotiation state
S2N_RENEG_START_MARKER = "RENEGOTIATE"
S2N_RENEG_SUCCESS_MARKER = "s2n is ready, again"
OPENSSL_RENEG_REQ_MARKER = "SSL_accept:SSLv3/TLS write hello request"
OPENSSL_RENEG_WARN_MARKER = "SSL3 alert read:warning:no renegotiation"


# Methods to check renegotiation state
def renegotiate_was_requested(openssl_results):
    return to_bytes(OPENSSL_RENEG_REQ_MARKER) in openssl_results.stderr


def renegotiate_was_rejected(openssl_results):
    return to_bytes(OPENSSL_RENEG_WARN_MARKER) in openssl_results.stderr


def renegotiate_was_started(s2n_results):
    return to_bytes(S2N_RENEG_START_MARKER) in s2n_results.stdout


def renegotiate_was_successful(s2n_results):
    return renegotiate_was_started(s2n_results) and \
        to_bytes(S2N_RENEG_SUCCESS_MARKER) in s2n_results.stdout


# Basic conversion methods
def to_bytes(val):
    return str(val).encode('utf-8')


def to_marker(val):
    return bytes(val).decode('utf-8')


"""
Msg handles translating a series of human-readable messages into the "markers" required
by the integrationv2 framework.

The integrationv2 framework controls process IO with various types of "markers".
Actions like writing data to a process's stdin or shutting down a process's stdin
can only occur if specific "markers" are read from the process's stdio. This makes
a simple scenario like a client and server taking turns sending application data require
careful construction of the data_to_send, send_marker, and close_marker options.

For simplicity, "Msg" currently assumes:
- s2n sends first. This lets us assume the first send_marker is S2N.get_send_marker().
- The server sends last. This lets us assume that only the client needs a close_marker.
"""


class Msg(object):
    def __init__(self, mode, send_marker=None, ctrl_str=None):
        self.mode = mode
        # Indicates what stdio string should trigger this message.
        # Will default to the previous message (see Msg.send_markers).
        self.send_marker = send_marker
        # Indicates that the message will be consumed by the process itself
        # rather than sent to the peer. This means it will never appear in
        # the peer's stdio and cannot be used as a send_marker.
        self.ctrl = ctrl_str is not None
        if ctrl_str:
            self.data_str = ctrl_str
        else:
            self.data_str = mode.upper() + ":" + str(random.getrandbits(8 * 10))

    @staticmethod
    def data_to_send(messages, mode):
        data_bytes = []
        for message in messages:
            if message.mode is not mode:
                continue
            if message.ctrl:
                data_bytes.append(to_bytes(message.data_str))
            else:
                # Openssl processes initial ASCII characters strangely,
                # but our framework is not good at handling non-ASCII characters due
                # to inconsistent use of bytes vs decode and str vs encode.
                # As a workaround, just prepend a throwaway non-ASCII utf-8 character.
                data_bytes.append(bytes([0xc2, 0xbb]) + to_bytes(message.data_str))
        # We assume that the client will close the connection.
        # Give the server one last message to send without a corresponding send_marker.
        # The message will never be sent, but waiting to send it will prevent the server
        # from closing the connection before the client can.
        if mode is Provider.ServerMode:
            data_bytes.append(to_bytes("Placeholder to prevent server socket close"))
        return data_bytes

    @staticmethod
    def expected_output(messages, mode):
        return [to_bytes(message.data_str) for message in messages if not message.ctrl and message.mode is not mode]

    @staticmethod
    def send_markers(messages, mode):
        send_markers = []
        for i, message in enumerate(messages):
            if message.mode is not mode:
                continue
            elif message.send_marker:
                send_markers.append(message.send_marker)
            elif i == 0:
                # Assume that the first sender is s2n
                send_markers.append(S2N.get_send_marker())
            else:
                previous = messages[i-1]
                assert (previous.mode is not mode)
                send_markers.append(previous.data_str)
        return send_markers

    @staticmethod
    def close_marker(messages):
        # Assume that the last sender is the server
        assert (messages[-1].mode is Provider.ServerMode)
        output = Msg.expected_output(messages, Provider.ClientMode)
        return to_marker(output[-1])

    @staticmethod
    def debug(messages):
        print(f'client data to send: {Msg.data_to_send(messages, Provider.ClientMode)}')
        print(f'server data to send: {Msg.data_to_send(messages, Provider.ServerMode)}')
        print(f'client send markers: {Msg.send_markers(messages, Provider.ClientMode)}')
        print(f'server send markers: {Msg.send_markers(messages, Provider.ServerMode)}')
        print(f'client close_marker: {Msg.close_marker(messages)}')
        print(f'client expected output: {Msg.expected_output(messages, Provider.ClientMode)}')
        print(f'server expected output: {Msg.expected_output(messages, Provider.ServerMode)}')


# The order of messages that will trigger renegotiation
# and verify sending and receiving continues to work afterwards.
RENEG_MESSAGES = [
    # Client sends first message
    Msg(Provider.ClientMode),
    # Server initiates renegotiation
    Msg(Provider.ServerMode, ctrl_str=OPENSSL_RENEG_CTRL_CMD),
    # Server sends first message
    Msg(Provider.ServerMode, send_marker=OPENSSL_RENEG_REQ_MARKER),
    # Client and Server exchange several more messages
    Msg(Provider.ClientMode),
    Msg(Provider.ServerMode),
    Msg(Provider.ClientMode),
    Msg(Provider.ServerMode),
]


def basic_reneg_test(managed_process, cipher, curve, certificate, protocol, provider, messages=RENEG_MESSAGES, reneg_option=None):
    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        key=certificate.key,
        cert=certificate.cert,
        protocol=protocol,
        insecure=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.data_to_send = Msg.data_to_send(messages, Provider.ClientMode)
    client_options.use_client_auth = True
    if reneg_option:
        client_options.extra_flags = [S2N_RENEG_OPTION, reneg_option]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.data_to_send = Msg.data_to_send(messages, Provider.ServerMode)

    server = managed_process(provider, server_options,
                             send_marker=Msg.send_markers(messages, Provider.ServerMode),
                             timeout=8
                             )

    s2n_client = managed_process(S2N, client_options,
                                 send_marker=Msg.send_markers(messages, Provider.ClientMode),
                                 close_marker=Msg.close_marker(messages),
                                 timeout=8
                                 )

    return (s2n_client, server)


"""
Renegotiation request ignored by s2n-tls client.

This tests the default behavior for customers who do not enable renegotiation.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_ignores_openssl_hello_request(managed_process, cipher, curve, certificate, protocol, provider):
    (s2n_client, server) = basic_reneg_test(managed_process, cipher, curve, certificate, protocol, provider)

    for results in server.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ServerMode):
            assert output in results.stdout
        assert renegotiate_was_requested(results)
        assert not renegotiate_was_rejected(results)

    for results in s2n_client.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ClientMode):
            assert output in results.stdout
        assert not renegotiate_was_started(results)


"""
Renegotiation request rejected by s2n-tls client.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_rejects_openssl_hello_request(managed_process, cipher, curve, certificate, protocol, provider):
    (s2n_client, server) = basic_reneg_test(managed_process, cipher, curve, certificate, protocol, provider,
                                            reneg_option=S2N_RENEG_REJECT)

    for results in server.get_results():
        assert renegotiate_was_requested(results)
        assert renegotiate_was_rejected(results)

    for results in s2n_client.get_results():
        assert results.exit_code != 0
        assert not renegotiate_was_started(results)
        assert to_bytes("Received alert: 40") in results.stderr


"""
Renegotiation request accepted by s2n-tls client.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_renegotiate_with_openssl(managed_process, cipher, curve, certificate, protocol, provider):
    (s2n_client, server) = basic_reneg_test(managed_process, cipher, curve, certificate, protocol, provider,
                                            reneg_option=S2N_RENEG_ACCEPT)

    for results in server.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ServerMode):
            assert output in results.stdout
        assert renegotiate_was_requested(results)
        assert not renegotiate_was_rejected(results)

    for results in s2n_client.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ClientMode):
            assert output in results.stdout
        assert renegotiate_was_successful(results)


"""
Renegotiation request with client auth accepted by s2n-tls client.

The openssl server does not require client auth during the first handshake,
but does require client auth during the second handshake.
"""


@pytest.mark.flaky(reruns=3, reruns_delay=1, condition=platform.machine().startswith("aarch"))
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_renegotiate_with_client_auth_with_openssl(managed_process, cipher, curve, certificate, protocol, provider):
    # We want to use the same messages to test renegotiation,
    # but with 'R' instead of 'r' to trigger the Openssl renegotiate request.
    messages = copy.deepcopy(RENEG_MESSAGES)
    for m in messages:
        if m.ctrl:
            m.data_str = 'R\n'

    client_auth_marker = "|CLIENT_AUTH"
    no_client_cert_marker = "|NO_CLIENT_CERT"

    (s2n_client, server) = basic_reneg_test(managed_process, cipher, curve, certificate, protocol, provider,
                                            messages=messages, reneg_option=S2N_RENEG_WAIT)

    for results in server.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ServerMode):
            assert output in results.stdout
        assert renegotiate_was_requested(results)
        assert not renegotiate_was_rejected(results)

    for results in s2n_client.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ClientMode):
            assert output in results.stdout
        assert renegotiate_was_successful(results)
        stdout_str = str(results.stdout)

    # The first handshake must not have done client auth
    init_finishes = stdout_str.find(S2N.get_send_marker())
    assert client_auth_marker not in stdout_str[:init_finishes]

    # The second handshake must have done client auth
    reneg_finishes = stdout_str.find(S2N_RENEG_SUCCESS_MARKER)
    assert client_auth_marker in stdout_str[init_finishes:reneg_finishes]
    assert no_client_cert_marker not in stdout_str[init_finishes:reneg_finishes]


"""
The s2n-tls client successfully reads ApplicationData during the renegotiation handshake.
"""


@pytest.mark.flaky(reruns=3, reruns_delay=1, condition=platform.machine().startswith("aarch"))
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_renegotiate_with_app_data_with_openssl(managed_process, cipher, curve, certificate, protocol, provider):
    first_server_app_data = Msg.expected_output(RENEG_MESSAGES, Provider.ClientMode)[0]
    (s2n_client, server) = basic_reneg_test(managed_process, cipher, curve, certificate, protocol, provider,
                                            reneg_option=S2N_RENEG_WAIT)

    for results in server.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ServerMode):
            assert output in results.stdout
        assert renegotiate_was_requested(results)
        assert not renegotiate_was_rejected(results)

    for results in s2n_client.get_results():
        results.assert_success()
        for output in Msg.expected_output(RENEG_MESSAGES, Provider.ClientMode):
            assert output in results.stdout
        assert renegotiate_was_successful(results)
        stdout_str = str(results.stdout)

    # In order to test the case where application data is received during renegotiation,
    # we must verify that the data was received after renegotiation started but before the new handshake finished.
    reneg_starts = stdout_str.find(S2N_RENEG_START_MARKER)
    reneg_finishes = stdout_str.find(S2N_RENEG_SUCCESS_MARKER)
    assert to_marker(first_server_app_data) in stdout_str[reneg_starts:reneg_finishes]
