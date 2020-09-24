import copy
import pytest

from configuration import available_ports
from common import ProviderOptions, Protocols, Certificates, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, JavaSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version

@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", [Certificates.ECDSA_384], ids=get_parameter_name)
def test_s2n_server_happy_path(managed_process, certificate, protocol):

    port = next(available_ports)
    random_bytes = data_bytes(100)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        protocol=protocol,
        data_to_send=random_bytes)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(JavaSSL, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(protocol, S2N)

    for results in server.get_results():
        assert results.exception is None
        ''' 
        The JDK sends a user_canceled alert as well as a close_notify alert after 
        a connection closes, so s2n will register the alert and complain. The way
        to test that a handshake successfully completed is to check that the protocol
        versions are correct.
        '''
        assert results.exit_code == 1
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout

