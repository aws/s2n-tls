import copy
import platform
import pytest
import re

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, MINIMAL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes

PADDING_SIZE_SMALL = 250
PADDING_SIZE_MEDIUM = 1000
PADDING_SIZE_MAX = 1 << 14

PADDING_SIZES = [
    PADDING_SIZE_SMALL,
    PADDING_SIZE_MEDIUM,
    PADDING_SIZE_MAX
]

# arbitrarily large payload size
PAYLOAD_SIZE = 1024

OPENSSL_RECORD_WRITTEN_PATTERN = r"write to .*?\\n(.*?)\\n"
OPENSSL_APP_DATA_HEADER_PATTERN = r"17 03 03 ([0-9a-f]{2} [0-9a-f]{2})"
RECORD_SIZE_GROUP = 1


def strip_string_of_bytes(s: str) -> str:
    # s has the form `b'<>'`. We need to strip the literal `b'` and the last `'`
    return s[2:-1]


def get_payload_size_from_openssl_trace(record_size_bytes: str) -> int:
    # record_size_bytes is in the form XX XX where X is a hex digit
    size_in_hex = record_size_bytes.replace(' ', '')
    size = int(size_in_hex, 16)
    # record includes 16 bytes of aead tag
    return size - 16


def assert_openssl_records_are_padded_correctly(openssl_output: str, padding_size: int):
    number_of_app_data_records = 0

    records_written = re.findall(
        OPENSSL_RECORD_WRITTEN_PATTERN, openssl_output)
    for record_prefix in records_written:
        app_data_header = re.search(
            OPENSSL_APP_DATA_HEADER_PATTERN, record_prefix)
        if app_data_header:
            size_bytes = app_data_header.group(RECORD_SIZE_GROUP)
            size = get_payload_size_from_openssl_trace(size_bytes)

            assert size > 0
            assert size % padding_size == 0

            number_of_app_data_records += 1

    # The client and server write a variable number of encrypted handshake records,
    # but each write at least one (Finished). We also send at least one ApplicationData record.
    assert number_of_app_data_records >= 2


def test_nothing():
    """
    Sometimes the record padding test parameters in combination with the s2n libcrypto
    results in no test cases existing. In this case, pass a nothing test to avoid
    marking the entire codebuild run as failed.
    """
    assert True


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
# only tls 1.3 supports record padding
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("padding_size", PADDING_SIZES, ids=get_parameter_name)
def test_s2n_server_handles_padded_records(managed_process, cipher, provider, curve, protocol, certificate,
                                           padding_size):
    port = next(available_ports)

    random_bytes = data_bytes(PAYLOAD_SIZE)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        cert=certificate.cert,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol,
        extra_flags=['-record_padding', padding_size]
    )

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.extra_flags = None

    s2nd = managed_process(S2N, server_options, timeout=5)
    openssl = managed_process(provider, client_options, timeout=5)

    for client_results in openssl.get_results():
        client_results.assert_success()
        assert_openssl_records_are_padded_correctly(
            str(client_results.stdout), padding_size)

    expected_version = get_expected_s2n_version(protocol, provider)

    for server_results in s2nd.get_results():
        server_results.assert_success()
        # verify that the payload was correctly received by the server
        assert random_bytes in server_results.stdout
        # verify that the version was correctly negotiated
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in server_results.stdout
        # verify that the cipher was correctly negotiated
        assert to_bytes("Cipher negotiated: {}".format(
            cipher.name)) in server_results.stdout


@pytest.mark.flaky(reruns=5, reruns_delay=2, condition=platform.machine().startswith("aarch"))
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
# only tls 1.3 supports record padding
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("padding_size", PADDING_SIZES, ids=get_parameter_name)
def test_s2n_client_handles_padded_records(managed_process, cipher, provider, curve, protocol, certificate,
                                           padding_size):
    port = next(available_ports)

    client_random_bytes = data_bytes(PAYLOAD_SIZE)
    server_random_bytes = data_bytes(PAYLOAD_SIZE)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        curve=curve,
        cert=certificate.cert,
        key=certificate.key,
        insecure=True,
        protocol=protocol,
        data_to_send=server_random_bytes,
        extra_flags=['-record_padding', padding_size]
    )

    client_options = copy.copy(server_options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = None
    client_options.data_to_send = client_random_bytes

    # openssl will send its response after it has received s2nc's record
    openssl = managed_process(provider, server_options,
                              timeout=5, send_marker=strip_string_of_bytes(str(client_random_bytes)))

    # s2nc will wait until it has received the server's response before closing
    s2nc = managed_process(S2N, client_options, timeout=5,
                           close_marker=strip_string_of_bytes(str(server_random_bytes)))

    expected_version = get_expected_s2n_version(protocol, provider)
    for client_results in s2nc.get_results():
        client_results.assert_success()
        # assert that the client has received server's application payload
        assert server_random_bytes in client_results.stdout
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in client_results.stdout
        assert to_bytes("Cipher negotiated: {}".format(
            cipher.name)) in client_results.stdout

    for server_results in openssl.get_results():
        server_results.assert_success()
        assert_openssl_records_are_padded_correctly(
            str(server_results.stdout), padding_size)
