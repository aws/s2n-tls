import pytest
import copy
import os

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, to_bytes

S2N_RESUMPTION_MARKER = to_bytes("Resumed session")
CLOSE_MARKER_BYTES = data_bytes(10)

TICKET_FILE = 'ticket'
RESUMPTION_PROTOCOLS = [Protocols.TLS12, Protocols.TLS13]


"""
An old S2N server can resume a session with a new S2N server's session ticket. 
Tests that S2N tickets are backwards-compatible.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", RESUMPTION_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2n_old_server_new_ticket(managed_process, tmp_path, cipher, curve, certificate, protocol, provider,
                                   other_provider):
    ticket_file = str(tmp_path / TICKET_FILE)
    assert not os.path.exists(ticket_file)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = ['-sess_out', ticket_file]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.data_to_send = CLOSE_MARKER_BYTES

    s2n_server = managed_process(
        S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(provider, client_options,
                             close_marker=str(CLOSE_MARKER_BYTES))

    for results in client.get_results():
        results.assert_success()

    for results in s2n_server.get_results():
        results.assert_success()

    assert os.path.exists(ticket_file)
    client_options.extra_flags = ['-sess_in', ticket_file]
    server_options.use_mainline_version = True

    s2n_server = managed_process(
        S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(provider, client_options,
                             close_marker=str(CLOSE_MARKER_BYTES))

    for results in client.get_results():
        results.assert_success()

    for results in s2n_server.get_results():
        results.assert_success()
        assert S2N_RESUMPTION_MARKER in results.stdout


"""
A new S2N server can resume a session with an old S2N server's session ticket. 
Tests that S2N tickets are forwards-compatible.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", RESUMPTION_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2n_new_server_old_ticket(managed_process, tmp_path, cipher, curve, certificate, protocol, provider,
                                   other_provider):
    ticket_file = str(tmp_path / TICKET_FILE)
    assert not os.path.exists(ticket_file)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = ['-sess_out', ticket_file]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.use_mainline_version = True
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.data_to_send = CLOSE_MARKER_BYTES

    s2n_server = managed_process(
        S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(provider, client_options,
                             close_marker=str(CLOSE_MARKER_BYTES))

    for results in client.get_results():
        results.assert_success()

    for results in s2n_server.get_results():
        results.assert_success()

    assert os.path.exists(ticket_file)
    client_options.extra_flags = ['-sess_in', ticket_file]
    server_options.use_mainline_version = False

    s2n_server = managed_process(
        S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(provider, client_options,
                             close_marker=str(CLOSE_MARKER_BYTES))

    for results in client.get_results():
        results.assert_success()

    for results in s2n_server.get_results():
        results.assert_success()
        assert S2N_RESUMPTION_MARKER in results.stdout


"""
An old S2N client can resume a session with an new S2N client's session ticket. 
Tests that S2N tickets are backwards-compatible. In our client tests we use an S2N
server because the Openssl server uses a different ticket key for each session.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", RESUMPTION_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2n_old_client_new_ticket(managed_process, tmp_path, cipher, curve, certificate, protocol, provider,
                                   other_provider):
    ticket_file = str(tmp_path / TICKET_FILE)
    assert not os.path.exists(ticket_file)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = ['--ticket-out', ticket_file]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in s2n_client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()

    assert os.path.exists(ticket_file)
    client_options.extra_flags = ['--ticket-in', ticket_file]
    client_options.use_mainline_version = True

    server = managed_process(provider, server_options)
    s2n_client = managed_process(other_provider, client_options)

    for results in s2n_client.get_results():
        results.assert_success()
        assert S2N_RESUMPTION_MARKER in results.stdout

    for results in server.get_results():
        results.assert_success()
        assert S2N_RESUMPTION_MARKER in results.stdout


"""
A new S2N client can resume a session with an old S2N client's session ticket. 
Tests that S2N tickets are forwards-compatible.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", RESUMPTION_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2n_new_client_old_ticket(managed_process, tmp_path, cipher, curve, certificate, protocol, provider,
                                   other_provider):
    ticket_file = str(tmp_path / TICKET_FILE)
    assert not os.path.exists(ticket_file)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = ['--ticket-out', ticket_file]
    client_options.use_mainline_version = True

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in s2n_client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()

    assert os.path.exists(ticket_file)
    client_options.extra_flags = ['--ticket-in', ticket_file]
    client_options.use_mainline_version = False

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in s2n_client.get_results():
        results.assert_success()
        assert S2N_RESUMPTION_MARKER in results.stdout

    for results in server.get_results():
        results.assert_success()
        assert S2N_RESUMPTION_MARKER in results.stdout
