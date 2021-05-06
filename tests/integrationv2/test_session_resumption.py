import copy
import os
import pytest
import time

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS, TLS13_CIPHERS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, get_expected_openssl_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [p for p in PROTOCOLS if p != Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("use_ticket", [True, False])
def test_session_resumption_s2n_server(managed_process, cipher, curve, protocol, provider, certificate, use_ticket):
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.reconnects_before_exit = 6
    server_options.mode = Provider.ServerMode
    server_options.use_session_ticket=use_ticket,
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(bytes("Session-ID:".encode('utf-8'))) == 6

    expected_version = get_expected_s2n_version(protocol, OpenSSL)

    # S2N should indicate the procotol version in a successful connection.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(bytes("Actual protocol version: {}".format(expected_version).encode('utf-8'))) == 6


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [p for p in PROTOCOLS if p != Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("use_ticket", [True, False])
def test_session_resumption_s2n_client(managed_process, cipher, curve, protocol, provider, certificate, use_ticket):
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=True,
        use_session_ticket=use_ticket,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.reconnects_before_exit = 6
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.use_session_ticket = False

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    expected_version = get_expected_s2n_version(protocol, OpenSSL)
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(bytes("Actual protocol version: {}".format(expected_version).encode('utf-8'))) == 6

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(bytes("6 server accepts that finished".encode('utf-8')))


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_tls13_session_resumption_s2n_server(managed_process, cipher, curve, protocol, provider, certificate):
    port = str(next(available_ports))

    ticket_filename = 'session_ticket_' + port

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=False,
        extra_flags = ['-sess_out', ticket_filename],
        data_to_send = data_bytes(4096),
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.use_session_ticket = True
    server_options.extra_flags = None

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    # Client inputs stored session ticket to resume a session
    assert os.path.exists(ticket_filename)
    client_options.extra_flags = ['-sess_in', ticket_filename]

    port = str(next(available_ports))
    client_options.port = port
    server_options.port = port

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    openssl_version = get_expected_openssl_version(protocol)
    s2n_version = get_expected_s2n_version(protocol, OpenSSL)

    # The client should have received a session ticket
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b'Post-Handshake New Session Ticket arrived:' in results.stdout
        assert bytes("Protocol  : {}".format(openssl_version).encode('utf-8')) in results.stdout

    # The server should indicate a session has been resumed
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b'Resumed session' in results.stdout
        assert bytes("Actual protocol version: {}".format(s2n_version).encode('utf-8')) in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_tls13_session_resumption_s2n_client(managed_process, cipher, curve, protocol, provider, certificate):
    port = str(next(available_ports))

    random_bytes = data_bytes(64)
    num_full_connections = 1
    num_resumed_connections = 5

    server_close_marker = b'Client has finished sending data'

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        use_session_ticket=True,
        data_to_send=server_close_marker,
        reconnect=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.use_session_ticket = False
    server_options.reconnects_before_exit = num_resumed_connections + num_full_connections
    client_send_marker = b"Server has finished sending data"
    server_options.data_to_send = [random_bytes, random_bytes, random_bytes, random_bytes, client_send_marker]

    send_marker = 'Secure Renegotiation IS supported'
    server = managed_process(provider, server_options, timeout=5, send_marker=send_marker, close_marker=str(server_close_marker))
    client = managed_process(S2N, client_options, timeout=5, send_marker=str(client_send_marker))

    s2n_version = get_expected_s2n_version(protocol, OpenSSL)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(b'Resumed session') == num_resumed_connections
        assert bytes("Actual protocol version: {}".format(s2n_version).encode('utf-8')) in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stderr.count(b'SSL_accept:SSLv3/TLS write certificate') == num_full_connections
