import copy
import pytest

from configuration import available_ports, TLS13_CIPHERS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
def test_s2n_server_key_update(managed_process, cipher):
    host = "localhost"
    port = next(available_ports)

    update_requested = b"K"
    server_data = data_bytes(10)
    client_data = data_bytes(10)
    starting_marker = "Verify return code"
    key_update_marker = "KEYUPDATE"

    send_marker_list = [starting_marker, key_update_marker]

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        cipher=cipher,
        data_to_send=[update_requested, client_data],
        insecure=True,
        protocol=Protocols.TLS13,
    )

    server_options = copy.copy(client_options)

    server_options.mode = Provider.ServerMode
    server_options.key = "../pems/ecdsa_p384_pkcs1_key.pem"
    server_options.cert = "../pems/ecdsa_p384_pkcs1_cert.pem"
    server_options.data_to_send = [server_data]

    server = managed_process(
        S2N, server_options, send_marker=[str(client_data)], timeout=5
    )
    client = managed_process(
        OpenSSL,
        client_options,
        send_marker=send_marker_list,
        close_marker=str(server_data),
        timeout=5,
    )

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert key_update_marker in str(results.stderr)
        assert server_data in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert client_data in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
def test_s2n_client_key_update(managed_process, cipher):
    host = "localhost"
    port = next(available_ports)

    update_requested = b"K\n"
    server_data = data_bytes(10)
    client_data = data_bytes(10)
    # Last statement printed out by Openssl after handshake
    starting_marker = "Secure Renegotiation IS supported"
    key_update_marker = "TLSv1.3 write server key update"
    read_key_update_marker = b"TLSv1.3 read client key update"

    send_marker_list = [starting_marker, key_update_marker]

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        cipher=cipher,
        data_to_send=[client_data],
        insecure=True,
        protocol=Protocols.TLS13,
    )

    server_options = copy.copy(client_options)

    server_options.mode = Provider.ServerMode
    server_options.key = "../pems/ecdsa_p384_pkcs1_key.pem"
    server_options.cert = "../pems/ecdsa_p384_pkcs1_cert.pem"
    server_options.data_to_send = [update_requested, server_data]

    server = managed_process(
        OpenSSL,
        server_options,
        send_marker=send_marker_list,
        close_marker=str(client_data),
        timeout=5,
    )
    client = managed_process(
        S2N,
        client_options,
        send_marker=[str(server_data)],
        close_marker=str(server_data),
        timeout=5,
    )

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert server_data in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert read_key_update_marker in results.stderr
        assert client_data in results.stdout
