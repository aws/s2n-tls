import copy
import os
import pytest
import time
from enum import Enum
from collections import namedtuple

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS, TLS13_CIPHERS
from common import ProviderOptions, Protocols, Curves, data_bytes
from fixtures import managed_process
from providers import Provider, S2N as S2NBase, OpenSSL as OpenSSLBase
from utils import invalid_test_parameters, get_parameter_name, to_bytes

TICKET_FILE = 'ticket'
EARLY_DATA_FILE = 'early_data'

MAX_EARLY_DATA = 500 # Arbitrary largish number
DATA_TO_SEND = data_bytes(500) # Arbitrary large number

NUM_RESUMES = 5 # Hardcoded for s2nc --reconnect
NUM_CONNECTIONS = NUM_RESUMES + 1 # resumes + initial

S2N_DEFAULT_CURVE = Curves.X25519
S2N_UNSUPPORTED_CURVE = 'X448' # We have no plans to support this curve any time soon
S2N_HRR_CURVES = list(curve for curve in ALL_TEST_CURVES if curve != S2N_DEFAULT_CURVE)

S2N_EARLY_DATA_RECV_MARKER = "Early Data received: "
S2N_EARLY_DATA_STATUS_MARKER = "Early Data status: {status}"
S2N_EARLY_DATA_ACCEPTED_MARKER = S2N_EARLY_DATA_STATUS_MARKER.format(status="ACCEPTED")
S2N_EARLY_DATA_REJECTED_MARKER = S2N_EARLY_DATA_STATUS_MARKER.format(status="REJECTED")
S2N_EARLY_DATA_NOT_REQUESTED_MARKER = S2N_EARLY_DATA_STATUS_MARKER.format(status="NOT REQUESTED")


class S2N(S2NBase):
    def __init__(self, options: ProviderOptions):
        S2NBase.__init__(self, options)

    def setup_client(self):
        cmd_line = S2NBase.setup_client(self)
        early_data_file = self.options.early_data_file
        if early_data_file and os.path.exists(early_data_file):
            cmd_line.extend(['--early-data', early_data_file])
        return cmd_line

    def setup_server(self):
        cmd_line = S2NBase.setup_server(self)
        cmd_line.extend(['--max-early-data', self.options.max_early_data])
        return cmd_line


class OpenSSL(OpenSSLBase):
    def __init__(self, options: ProviderOptions):
        OpenSSLBase.__init__(self, options)

    def setup_client(self):
        cmd_line = OpenSSLBase.setup_client(self)
        early_data_file = self.options.early_data_file
        if early_data_file and os.path.exists(early_data_file):
            cmd_line.extend(['-early_data', early_data_file])
        ticket_file = self.options.ticket_file
        if ticket_file:
            if os.path.exists(ticket_file):
                cmd_line.extend(['-sess_in', ticket_file])
            else:
                cmd_line.extend(['-sess_out', self.options.ticket_file])
        return cmd_line

    def setup_server(self):
        cmd_line = OpenSSLBase.setup_server(self)
        if self.options.max_early_data > 0:
            cmd_line.extend(['-early_data'])
        return cmd_line


# The `-reconnect` option is broken for TLS1.3 in OpenSSL s_client: https://github.com/openssl/openssl/issues/8517
# The `-sess_in`/`-sess_out` options can be used instead, but don't have an s2nc equivalent.
# As we add more providers, we may need both a `-reconnect`-like and a `-sess_in/out`-like S2N server test,
# but for now we can just use `-sess_in/out` and cover the S2N->S2N case in the S2N client tests.
CLIENT_PROVIDERS = [ OpenSSL ]
SERVER_PROVIDERS = [ OpenSSL, S2N ]


def get_early_data_bytes(file_path, early_data_size):
    early_data = data_bytes(early_data_size)
    with open(file_path, 'wb') as fout:
        fout.write(early_data)
    return early_data


def get_ticket_from_s2n_server(options, managed_process, provider, certificate):
    port = next(available_ports)

    """
    Generally clients start checking for stdin EoF to exit as soon as they finish the handshake.
    To make sure the client reliably receives the post-handshake NST,
    do NOT indicate stdin EoF until after some data has been received from the server.
    """
    close_marker_bytes = data_bytes(10)

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.port = port

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.port = port
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.data_to_send = close_marker_bytes

    assert not os.path.exists(options.ticket_file)

    s2n_server = managed_process(S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(provider, client_options, close_marker=str(close_marker_bytes))

    for results in s2n_server.get_results():
        results.assert_success()

    for results in client.get_results():
        results.assert_success()

    assert os.path.exists(options.ticket_file)


"""
Basic S2N server happy case.

We make one full connection to get a session ticket with early data enabled,
then another resumption connection with early data.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", CLIENT_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_server_with_early_data(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    ticket_file = str(tmp_path / TICKET_FILE)
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        data_to_send=DATA_TO_SEND,
    )
    options.ticket_file = ticket_file
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    get_ticket_from_s2n_server(options, managed_process, provider, certificate)

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options)

    for results in client.get_results():
        results.assert_success()

    for results in s2n_server.get_results():
        results.assert_success()
        assert (to_bytes(S2N_EARLY_DATA_RECV_MARKER) + early_data) in results.stdout
        assert to_bytes(S2N_EARLY_DATA_ACCEPTED_MARKER) in results.stdout
        assert DATA_TO_SEND in results.stdout


"""
Basic S2N client happy case.

The S2N client tests session resumption by repeatedly reconnecting.
That means we don't need to manually perform the initial full connection, and there is no external ticket file.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", SERVER_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_client_with_early_data(managed_process, tmp_path, cipher, protocol, provider, certificate, early_data_size):
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        reconnect=True,
    )
    options.ticket_file = None
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key # Required for the initial connection
    server_options.cert = certificate.cert # Required for the initial connection
    server_options.reconnects_before_exit = NUM_CONNECTIONS

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in s2n_client.get_results():
        results.assert_success()
        assert results.stdout.count(to_bytes(S2N_EARLY_DATA_ACCEPTED_MARKER)) == NUM_RESUMES

    for results in server.get_results():
        results.assert_success()
        assert results.stdout.count(early_data) == NUM_RESUMES


"""
Verify that the S2N client doesn't request early data when a server doesn't support early data.

We repeatedly reconnect with max_early_data set to 0. This is basically a test from
test_session_resumption but with validation that no early data is sent.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", SERVER_PROVIDERS, ids=get_parameter_name)
def test_s2n_client_without_early_data(managed_process, tmp_path, cipher, protocol, provider, certificate):
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, MAX_EARLY_DATA)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        reconnect=True,
    )
    options.ticket_file = None
    options.early_data_file = early_data_file
    options.max_early_data = 0

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key # Required for the initial connection
    server_options.cert = certificate.cert # Required for the initial connection
    server_options.reconnects_before_exit = NUM_CONNECTIONS

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in server.get_results():
        results.assert_success()
        assert early_data not in results.stdout

    for results in s2n_client.get_results():
        results.assert_success()
        assert results.stdout.count(to_bytes(S2N_EARLY_DATA_NOT_REQUESTED_MARKER)) == NUM_CONNECTIONS


"""
Test the S2N server rejecting early data.

We do this by disabling early data on the server after the ticket is issued.
When the client attempts to use the ticket to send early data, the server rejects the attempt.

We can't perform an S2N client version of this test because the S2N client performs its hardcoded
reconnects automatically, without any mechanism to modify the connection in between.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", CLIENT_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_server_with_early_data_rejected(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    ticket_file = str(tmp_path / TICKET_FILE)
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        data_to_send=DATA_TO_SEND,
    )
    options.ticket_file = ticket_file
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    get_ticket_from_s2n_server(options, managed_process, provider, certificate)
    options.max_early_data = 0

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options)

    for results in client.get_results():
        results.assert_success()

    for results in s2n_server.get_results():
        results.assert_success()
        assert to_bytes(S2N_EARLY_DATA_RECV_MARKER) not in results.stdout
        assert to_bytes(S2N_EARLY_DATA_REJECTED_MARKER) in results.stdout
        assert DATA_TO_SEND in results.stdout


"""
Test the S2N client attempting to send early data, but the server triggering a hello retry.

We trigger the HRR by configuring the server to only accept curves that the S2N client
does not send key shares for.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", S2N_HRR_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", SERVER_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_client_with_early_data_rejected_via_hrr(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    if provider == S2N:
        pytest.skip("S2N does not respect ProviderOptions.curve, so does not trigger a retry")

    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        reconnect=True,
    )
    options.ticket_file = None
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key # Required for the initial connection
    server_options.cert = certificate.cert # Required for the initial connection
    server_options.reconnects_before_exit = NUM_CONNECTIONS

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in s2n_client.get_results():
        results.assert_success()
        assert results.stdout.count(to_bytes(S2N_EARLY_DATA_REJECTED_MARKER)) == NUM_RESUMES

    for results in server.get_results():
        results.assert_success()
        assert early_data not in results.stdout


"""
Test the S2N server rejecting early data because of a hello retry request.

In order to trigger a successful retry, we need to force the peer to offer us a key share that
S2N doesn't support while still supporting at least one curve S2N does support.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", CLIENT_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_server_with_early_data_rejected_via_hrr(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    ticket_file = str(tmp_path / TICKET_FILE)
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=(S2N_UNSUPPORTED_CURVE + ":" + str(curve)),
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        data_to_send=DATA_TO_SEND,
    )
    options.ticket_file = ticket_file
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    get_ticket_from_s2n_server(options, managed_process, provider, certificate)

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options)

    for results in client.get_results():
        results.assert_success()
        assert early_data not in results.stdout

    for results in s2n_server.get_results():
        results.assert_success()
        assert to_bytes(S2N_EARLY_DATA_RECV_MARKER) not in results.stdout
        assert to_bytes(S2N_EARLY_DATA_REJECTED_MARKER) in results.stdout
        assert DATA_TO_SEND in results.stdout


"""
Test the S2N server fails if it receives too much early data.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", CLIENT_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("excess_early_data", [1, 10, MAX_EARLY_DATA])
def test_s2n_server_with_early_data_max_exceeded(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, excess_early_data):
    ticket_file = str(tmp_path / TICKET_FILE)
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, MAX_EARLY_DATA + excess_early_data)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        data_to_send=DATA_TO_SEND,
    )
    options.ticket_file = ticket_file
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA + excess_early_data

    get_ticket_from_s2n_server(options, managed_process, provider, certificate)
    options.max_early_data = MAX_EARLY_DATA

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options)

    for results in client.get_results():
        """
        We can't make any assertions about the client exit_code.
        To avoid blinding delays, s2nd doesn't call s2n_shutdown for a failed negotiation.
        That means that instead of sending close_notify, we just close the socket.
        Whether the peer interprets this as a failure or EoF depends on its state.
        """
        assert results.exception is None
        assert DATA_TO_SEND not in results.stdout

    for results in s2n_server.get_results():
        assert results.exception is None
        assert results.exit_code != 0
        # Full early data should not be reported
        assert early_data not in results.stdout
        # Partial early data should be reported
        assert (to_bytes(S2N_EARLY_DATA_RECV_MARKER) + early_data[:MAX_EARLY_DATA]) in results.stdout
        assert to_bytes("Bad message encountered") in results.stderr

