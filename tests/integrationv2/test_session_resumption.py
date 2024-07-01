import copy
import os
import platform
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS, TLS13_CIPHERS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [p for p in PROTOCOLS if p != Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("use_ticket", [True, False])
def test_session_resumption_s2n_server(managed_process, cipher, curve, certificate, protocol, provider, other_provider,
                                       use_ticket):
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.reconnects_before_exit = 6
    server_options.mode = Provider.ServerMode
    server_options.use_session_ticket = use_ticket,
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        results.assert_success()
        assert results.stdout.count(to_bytes("Session-ID:")) == 6

    expected_version = get_expected_s2n_version(protocol, OpenSSL)

    # S2N should indicate the procotol version in a successful connection.
    for results in server.get_results():
        results.assert_success()
        assert results.stdout.count(
            to_bytes("Actual protocol version: {}".format(expected_version))) == 6


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [p for p in PROTOCOLS if p != Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("use_ticket", [True, False])
def test_session_resumption_s2n_client(managed_process, cipher, curve, protocol, provider, other_provider, certificate,
                                       use_ticket):
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
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
        results.assert_success()
        assert results.stdout.count(
            to_bytes("Actual protocol version: {}".format(expected_version))) == 6

    for results in server.get_results():
        results.assert_success()
        assert results.stdout.count(to_bytes("6 server accepts that finished"))


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_tls13_session_resumption_s2n_server(managed_process, tmp_path, cipher, curve, certificate, protocol, provider,
                                             other_provider):
    port = str(next(available_ports))

    # Use temp directory to store session tickets
    p = tmp_path / 'ticket.pem'
    path_to_ticket = str(p)

    close_marker_bytes = data_bytes(10)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=False,
        extra_flags=['-sess_out', path_to_ticket],
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.use_session_ticket = True
    server_options.extra_flags = None
    server_options.data_to_send = close_marker_bytes

    server = managed_process(
        S2N, server_options, timeout=5, send_marker=S2N.get_send_marker())
    client = managed_process(provider, client_options,
                             timeout=5, close_marker=str(close_marker_bytes))

    # The client should have received a session ticket
    for results in client.get_results():
        results.assert_success()
        assert b'Post-Handshake New Session Ticket arrived:' in results.stdout

    for results in server.get_results():
        results.assert_success()
        # The first connection is a full handshake
        assert b'Resumed session' not in results.stdout

    # Client inputs received session ticket to resume a session
    assert os.path.exists(path_to_ticket)
    client_options.extra_flags = ['-sess_in', path_to_ticket]

    port = str(next(available_ports))
    client_options.port = port
    server_options.port = port

    server = managed_process(
        S2N, server_options, timeout=5, send_marker=S2N.get_send_marker())
    client = managed_process(provider, client_options,
                             timeout=5, close_marker=str(close_marker_bytes))

    s2n_version = get_expected_s2n_version(protocol, provider)

    # Client has not read server certificate message as this is a resumed session
    for results in client.get_results():
        results.assert_success()
        assert to_bytes(
            "SSL_connect:SSLv3/TLS read server certificate") not in results.stderr

    # The server should indicate a session has been resumed
    for results in server.get_results():
        results.assert_success()
        assert b'Resumed session' in results.stdout
        assert to_bytes("Actual protocol version: {}".format(
            s2n_version)) in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL, S2N], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_tls13_session_resumption_s2n_client(managed_process, cipher, curve, certificate, protocol, provider,
                                             other_provider):
    port = str(next(available_ports))

    # The reconnect option for s2nc allows the client to reconnect automatically
    # five times. In this test we expect one full connection and five resumption
    # connections.
    num_full_connections = 1
    num_resumed_connections = 5

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        use_session_ticket=True,
        reconnect=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.reconnects_before_exit = num_resumed_connections + num_full_connections

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    s2n_version = get_expected_s2n_version(protocol, provider)

    # s2nc indicates the number of resumed connections in its output
    for results in client.get_results():
        results.assert_success()
        assert results.stdout.count(
            b'Resumed session') == num_resumed_connections
        assert to_bytes("Actual protocol version: {}".format(
            s2n_version)) in results.stdout

    server_accepts_str = str(
        num_resumed_connections + num_full_connections) + " server accepts that finished"

    for results in server.get_results():
        results.assert_success()
        if provider is S2N:
            assert results.stdout.count(
                b'Resumed session') == num_resumed_connections
            assert to_bytes("Actual protocol version: {}".format(
                s2n_version)) in results.stdout
        else:
            assert to_bytes(server_accepts_str) in results.stdout
            # s_server only writes one certificate message in all of the connections
            assert results.stderr.count(
                b'SSL_accept:SSLv3/TLS write certificate') == num_full_connections


@pytest.mark.flaky(reruns=7, reruns_delay=2, condition=platform.machine().startswith("aarch"))
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2nd_falls_back_to_full_connection(managed_process, tmp_path, cipher, curve, certificate, protocol, provider,
                                            other_provider):
    port = str(next(available_ports))

    # Use temp directory to store session tickets
    p = tmp_path / 'ticket.pem'
    path_to_ticket = str(p)

    """
    This test will set up a full connection with an Openssl client and server to obtain
    a valid Openssl session ticket. Then, the Openssl client attempts to send the 
    received session ticket to an s2n server to resume a session. s2nd will fallback to
    a full connection as it does not recognize the session ticket.
    """
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=False,
        extra_flags=['-sess_out', path_to_ticket],
        data_to_send=data_bytes(4069),
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags = None

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # The client should have received a session ticket
    for results in client.get_results():
        results.assert_success()
        assert b'Post-Handshake New Session Ticket arrived:' in results.stdout

    for results in server.get_results():
        results.assert_success()
        # Server should have sent certificate message as this is a full connection
        assert b'SSL_accept:SSLv3/TLS write certificate' in results.stderr

    # Client inputs received session ticket to resume a session
    assert os.path.exists(path_to_ticket)
    client_options.extra_flags = ['-sess_in', path_to_ticket]

    port = str(next(available_ports))
    client_options.port = port
    server_options.port = port

    # Switch providers so now s2n is the server
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    s2n_version = get_expected_s2n_version(protocol, provider)

    # Client has read server certificate because this is a full connection
    for results in client.get_results():
        results.assert_success()
        assert to_bytes(
            "SSL_connect:SSLv3/TLS read server certificate") in results.stderr

    # The server should indicate a session has not been resumed
    for results in server.get_results():
        results.assert_success()
        assert b'Resumed session' not in results.stdout
        assert to_bytes("Actual protocol version: {}".format(
            s2n_version)) in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [p for p in PROTOCOLS if p < Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL, S2N], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_session_resumption_s2n_client_tls13_server_not_tls13(managed_process, cipher, curve, protocol, provider, other_provider, certificate):
    port = next(available_ports)

    # This test verifies that an S2N client that supports TLS1.3 can resume sessions
    # with a server that does not support TLS1.3

    # The reconnect option for s2nc allows the client to reconnect automatically
    # five times. In this test we expect one full connection and five resumption
    # connections.
    num_full_connections = 1
    num_resumed_connections = 5

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=True,
        use_session_ticket=True,
        protocol=Protocols.TLS13)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=True,
        use_session_ticket=False,
        protocol=protocol,
        reconnects_before_exit=num_resumed_connections + num_full_connections,
        key=certificate.key,
        cert=certificate.cert)

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    expected_version = get_expected_s2n_version(protocol, provider)
    server_accepts_str = str(
        num_resumed_connections + num_full_connections) + " server accepts that finished"

    for results in client.get_results():
        results.assert_success()
        assert results.stdout.count(
            b'Resumed session') == num_resumed_connections
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in results.stdout

    for results in server.get_results():
        results.assert_success()
        if provider is S2N:
            assert results.stdout.count(
                b'Resumed session') == num_resumed_connections
            assert to_bytes("Actual protocol version: {}".format(
                expected_version)) in results.stdout
        else:
            assert to_bytes(server_accepts_str) in results.stdout
