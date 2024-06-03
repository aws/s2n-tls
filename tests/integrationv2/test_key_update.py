import copy
import pytest

from configuration import available_ports, TLS13_CIPHERS
from common import ProviderOptions, Protocols, random_str
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name

SERVER_DATA = f"Some random data from the server:" + random_str(10)
CLIENT_DATA = f"Some random data from the client:" + random_str(10)


def test_nothing():
    """
    Sometimes the key update test parameters in combination with the s2n libcrypto
    results in no test cases existing. In this case, pass a nothing test to avoid
    marking the entire codebuild run as failed.
    """
    assert True


@pytest.mark.flaky(reruns=5)
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
def test_s2n_server_key_update(managed_process, cipher, provider, other_provider, protocol):
    host = "localhost"
    port = next(available_ports)

    update_requested = b"K"
    starting_marker = "Verify return code"
    key_update_marker = "KEYUPDATE"

    send_marker_list = [starting_marker, key_update_marker]

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        cipher=cipher,
        data_to_send=[update_requested, CLIENT_DATA.encode()],
        insecure=True,
        protocol=protocol,
    )

    server_options = copy.copy(client_options)

    server_options.mode = Provider.ServerMode
    server_options.key = "../pems/ecdsa_p384_pkcs1_key.pem"
    server_options.cert = "../pems/ecdsa_p384_pkcs1_cert.pem"
    server_options.data_to_send = [SERVER_DATA.encode()]

    server = managed_process(
        S2N, server_options, send_marker=CLIENT_DATA, timeout=30
    )
    client = managed_process(
        provider,
        client_options,
        send_marker=send_marker_list,
        close_marker=SERVER_DATA,
        timeout=30,
    )

    for results in client.get_results():
        results.assert_success()
        assert key_update_marker in str(results.stderr)
        assert SERVER_DATA.encode() in results.stdout

    for results in server.get_results():
        results.assert_success()
        assert CLIENT_DATA.encode() in results.stdout


@pytest.mark.flaky(reruns=5)
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
def test_s2n_client_key_update(managed_process, cipher, provider, other_provider, protocol):
    host = "localhost"
    port = next(available_ports)

    update_requested = b"K\n"
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
        data_to_send=[CLIENT_DATA.encode()],
        insecure=True,
        protocol=protocol,
    )

    server_options = copy.copy(client_options)

    server_options.mode = Provider.ServerMode
    server_options.key = "../pems/ecdsa_p384_pkcs1_key.pem"
    server_options.cert = "../pems/ecdsa_p384_pkcs1_cert.pem"
    server_options.data_to_send = [update_requested, SERVER_DATA.encode()]

    server = managed_process(
        provider,
        server_options,
        send_marker=send_marker_list,
        close_marker=CLIENT_DATA,
        timeout=30,
    )
    client = managed_process(
        S2N,
        client_options,
        send_marker=SERVER_DATA,
        close_marker=SERVER_DATA,
        timeout=30,
    )

    for results in client.get_results():
        results.assert_success()
        assert SERVER_DATA.encode() in results.stdout

    for results in server.get_results():
        results.assert_success()
        assert read_key_update_marker in results.stderr
        assert CLIENT_DATA.encode() in results.stdout
