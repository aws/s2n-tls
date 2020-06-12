import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROVIDERS, PROTOCOLS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", PROVIDERS)
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
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

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
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(protocol, provider)

    # The server is always S2N in this test, so we can examine
    # the stdout reliably.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_s2n_client_happy_path(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    # We can only send 4096 bytes here because of the way some servers chunk
    # output (when writing to stdout). If we send 8192 bytes, then openssl
    # will print some debugging information in the middle of our chunk.
    # We still want that debugging data in case of a failure, so we just
    # send less data, rather than lose debug information.
    random_bytes = data_bytes(4096)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    expected_version = get_expected_s2n_version(protocol, provider)

    # The client is always S2N in this test, so we can examine
    # the stdout reliably.
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout

    # The server will be one of all supported providers. We
    # just want to make sure there was no exception and that
    # the client exited cleanly.
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert random_bytes in results.stdout
