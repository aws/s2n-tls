import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, MINIMAL_TEST_CERTS, PROTOCOLS
from common import ProviderOptions, Protocols
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import OpenSSL, S2N, Provider
from utils import invalid_test_parameters, get_parameter_name, to_bytes


# NPN not supported in TLS1.3
TLS_PROTOCOLS = [x for x in PROTOCOLS if x.value < Protocols.TLS13.value]

# Output indicating NPN status
S2N_NPN_MARKER = "WITH_NPN"
S2N_APPLICATION_MARKER = "Application protocol: "
OPENSSL_SERVER_NPN_MARKER = "NEXTPROTO is "
# The OpenSSL client uses "(1)" to indicate that a protocol was selected from
# the server's advertised list. "(2)" indicates the client couldn't find any overlap
# with the server's list and had to select from its own list.
OPENSSL_CLIENT_NPN_MARKER = "Next protocol: (1) "
OPENSSL_CLIENT_NPN_NO_OVERLAP_MARKER = "Next protocol: (2) "

# Test lists
PROTOCOL_LIST = 'http/1.1,h2,h3'
PROTOCOL_LIST_ALT_ORDER = 'h2,h3,http/1.1'
PROTOCOL_LIST_NO_OVERLAP = 'spdy'


def s2n_client_npn_handshake(managed_process, cipher, curve, certificate, protocol, provider, server_list):
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
    # Flags to turn on NPN for s2nc
    client_options.extra_flags = ['--alpn', PROTOCOL_LIST, '--npn']

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    # Flags to turn on NPN for OpenSSL server
    server_options.extra_flags = ['-nextprotoneg', server_list]

    server = managed_process(provider, server_options, timeout=5)
    s2n_client = managed_process(S2N, client_options, timeout=5)

    return (s2n_client, server)


"""
The s2n-tls client successfully negotiates an application protocol using NPN.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TLS_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_npn(managed_process, cipher, curve, certificate, protocol, provider):
    s2n_client, server = s2n_client_npn_handshake(managed_process, cipher, curve, certificate, protocol, provider,
                                                  server_list=PROTOCOL_LIST)

    expected_protocol = 'http/1.1'

    for results in server.get_results():
        results.assert_success()
        assert to_bytes(OPENSSL_SERVER_NPN_MARKER + expected_protocol) in results.stdout

    for results in s2n_client.get_results():
        results.assert_success()
        assert to_bytes(S2N_NPN_MARKER) in results.stdout
        assert to_bytes(S2N_APPLICATION_MARKER + expected_protocol) in results.stdout


"""
The s2n-tls client chooses a server-preferred protocol.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TLS_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_npn_server_preference(managed_process, cipher, curve, certificate, protocol, provider):
    s2n_client, server = s2n_client_npn_handshake(managed_process, cipher, curve, certificate, protocol, provider,
                                                  server_list=PROTOCOL_LIST_ALT_ORDER)

    expected_protocol = 'h2'

    for results in server.get_results():
        results.assert_success()
        assert to_bytes(OPENSSL_SERVER_NPN_MARKER + expected_protocol) in results.stdout

    for results in s2n_client.get_results():
        results.assert_success()
        assert to_bytes(S2N_NPN_MARKER) in results.stdout
        assert to_bytes(S2N_APPLICATION_MARKER + expected_protocol) in results.stdout


"""
The s2n-tls client chooses its preferred protocol since there is no overlap.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TLS_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_client_npn_no_overlap(managed_process, cipher, curve, certificate, protocol, provider):
    s2n_client, server = s2n_client_npn_handshake(managed_process, cipher, curve, certificate, protocol, provider,
                                                  server_list=PROTOCOL_LIST_NO_OVERLAP)

    expected_protocol = 'http/1.1'

    for results in server.get_results():
        results.assert_success()
        assert to_bytes(OPENSSL_SERVER_NPN_MARKER + expected_protocol) in results.stdout

    for results in s2n_client.get_results():
        results.assert_success()
        assert to_bytes(S2N_NPN_MARKER) in results.stdout
        assert to_bytes(S2N_APPLICATION_MARKER + expected_protocol) in results.stdout


def s2n_server_npn_handshake(managed_process, cipher, curve, certificate, protocol, provider, server_list):
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
    # Flags to turn on NPN for OpenSSL client
    client_options.extra_flags = ['-nextprotoneg', PROTOCOL_LIST]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    # Flags to turn on NPN for s2nd.
    server_options.extra_flags = ['--alpn', server_list, '--npn']

    s2n_server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    return (client, s2n_server)


"""
The s2n-tls server successfully negotiates an application protocol using NPN.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TLS_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_server_npn(managed_process, cipher, curve, certificate, protocol, provider):
    # We only send one protocol on the s2n server
    # due to the fact that it re-purposes the alpn list(which only sends one protocol)
    # to work for the NPN list.
    client, s2n_server = s2n_server_npn_handshake(managed_process, cipher, curve, certificate, protocol, provider,
                                                  server_list='http/1.1')

    expected_protocol = 'http/1.1'

    for results in s2n_server.get_results():
        results.assert_success()
        assert to_bytes(S2N_NPN_MARKER) in results.stdout
        assert to_bytes(S2N_APPLICATION_MARKER + expected_protocol) in results.stdout

    for results in client.get_results():
        results.assert_success()
        assert to_bytes(OPENSSL_CLIENT_NPN_MARKER + expected_protocol) in results.stdout


"""
The s2n-tls server can handle the case where there is no mutually supported protocol and 
the client chooses its own protocol.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TLS_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_s2n_server_npn_no_overlap(managed_process, cipher, curve, certificate, protocol, provider):
    client, s2n_server = s2n_server_npn_handshake(managed_process, cipher, curve, certificate, protocol, provider,
                                                  server_list=PROTOCOL_LIST_NO_OVERLAP)

    expected_protocol = 'http/1.1'

    for results in s2n_server.get_results():
        results.assert_success()
        assert to_bytes(S2N_NPN_MARKER) in results.stdout
        assert to_bytes(S2N_APPLICATION_MARKER + expected_protocol) in results.stdout

    for results in client.get_results():
        results.assert_success()
        assert to_bytes(OPENSSL_CLIENT_NPN_NO_OVERLAP_MARKER + expected_protocol) in results.stdout
