import copy
import platform
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS
from common import ProviderOptions, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, JavaSSL, GnuTLS, SSLv3Provider
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL, GnuTLS, JavaSSL, SSLv3Provider])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_s2n_server_happy_path(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    # s2nd can receive large amounts of data because all the data is
    # echo'd to stdout unmodified. This lets us compare received to
    # expected easily.
    # We purposefully send a non block aligned number to make sure
    # nothing blocks waiting for more data.
    random_bytes = data_bytes(65519)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        cert=certificate.cert,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol
    )

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # The client will be one of all supported providers. We
    # just want to make sure there was no exception and that
    # the client exited cleanly.
    for client_results in client.get_results():
        client_results.assert_success()

    expected_version = get_expected_s2n_version(protocol, provider)

    # The server is always S2N in this test, so we can examine
    # the stdout reliably.
    for server_results in server.get_results():
        server_results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in server_results.stdout
        assert random_bytes in server_results.stdout

        if provider is not S2N:
            assert to_bytes("Cipher negotiated: {}".format(
                cipher.name)) in server_results.stdout


@pytest.mark.flaky(reruns=5, reruns_delay=2, condition=platform.machine().startswith("aarch"))
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL, GnuTLS, SSLv3Provider])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_s2n_client_happy_path(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    # We can only send 4096 - 1 (\n at the end) bytes here because of the
    # way some servers chunk output (when writing to stdout). If we send
    # 8192 bytes, then openssl will print some debugging information in
    # the middle of our chunk. We still want that debugging data in case
    # of a failure, so we just send less data, rather than lose debug
    # information.
    random_bytes = data_bytes(4095)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol,
    )

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    kill_marker = None
    if provider == GnuTLS:
        kill_marker = random_bytes

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options,
                             timeout=5, kill_marker=kill_marker)
    client = managed_process(S2N, client_options, timeout=5)

    expected_version = get_expected_s2n_version(protocol, provider)

    # The client is always S2N in this test, so we can examine
    # the stdout reliably.
    for client_results in client.get_results():
        client_results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in client_results.stdout

    # The server will be one of all supported providers. We
    # just want to make sure there was no exception and that
    # the client exited cleanly.
    for server_results in server.get_results():
        server_results.assert_success()
        # Avoid debugging information that sometimes gets inserted after the first character.
        assert any(
            [random_bytes[1:] in stream for stream in server_results.output_streams()])
