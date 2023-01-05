import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, MINIMAL_TEST_CERTS
from common import Ciphers, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes

PADDING_SIZE_MIN = 0
PADDING_SIZE_SMALL = 250
PADDING_SIZE_MEDIUM = 1000
PADDING_SIZE_MAX = 1 << 14

PADDING_SIZES = [
    PADDING_SIZE_MIN,
    PADDING_SIZE_SMALL,
    PADDING_SIZE_MEDIUM,
    PADDING_SIZE_MAX
]

PAYLOAD_SIZE_SMALL = 10
PAYLOAD_SIZE_MEDIUM = 100
# openssl has a max fragment length of 4096 bytes
PAYLOAD_SIZE_LARGE = 4096

OPENSSL_PAYLOAD_SIZES = [PAYLOAD_SIZE_SMALL,
                         PAYLOAD_SIZE_MEDIUM, PAYLOAD_SIZE_LARGE]

# https://www.rfc-editor.org/rfc/rfc5116
TLS13_CIPHERS_WITH_16_BYTE_TAGS = [
    Ciphers.AES128_GCM_SHA256,
    Ciphers.AES256_GCM_SHA384,
    Ciphers.CHACHA20_POLY1305_SHA256
]


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS_WITH_16_BYTE_TAGS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
# only tls 1.3 supports record padding
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("padded_block_size", PADDING_SIZES, ids=get_parameter_name)
@pytest.mark.parametrize("payload_size", OPENSSL_PAYLOAD_SIZES, ids=get_parameter_name)
def test_s2n_13_server_handles_padded_records(managed_process, cipher, provider, curve, protocol, certificate,
                                              padded_block_size, payload_size):
    port = next(available_ports)

    random_bytes = data_bytes(payload_size)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        cert=certificate.cert,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol,
        extra_flags=['-record_padding', padded_block_size]
    )

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.extra_flags = None

    s2nd = managed_process(S2N, server_options, timeout=5)
    openssl = managed_process(provider, client_options, timeout=5)

    expected_total_length = None
    if padded_block_size == 0:
        # if we aren't padding to some known block size, then the expected total length is
        # equal to the payload size + 16 bytes of AEAD + 1 byte for content type
        expected_total_length = payload_size + 16 + 1
    else:
        expected_total_length = padded_block_size + 16

    # In the TLS record header, the last two bytes are reserved for length
    hex_string = "{:04x}".format(expected_total_length)
    first_byte, second_byte = hex_string[:2], hex_string[2:]
    expected_record_header = "17 03 03 {} {}".format(first_byte, second_byte)

    for client_results in openssl.get_results():
        client_results.assert_success()
        # verify that the openssl is sending padded payloads with the expected size
        assert to_bytes(expected_record_header) in client_results.stdout

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


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
# only tls 1.3 supports record padding
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("padded_block_size", PADDING_SIZES, ids=get_parameter_name)
def test_s2n_13_client_handles_padded_records(managed_process, cipher, provider, curve, protocol, certificate,
                                              padded_block_size):
    port = next(available_ports)

    random_bytes = data_bytes(4095)
    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        curve=curve,
        cert=certificate.cert,
        key=certificate.key,
        insecure=True,
        protocol=protocol,
        # openssl errors when sending session tickets and when padding is set > 2075 bytes.
        extra_flags=['-num_tickets', 0, '-record_padding', padded_block_size]
    )

    client_options = copy.copy(server_options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = None
    client_options.data_to_send = random_bytes

    s2nc = managed_process(S2N, client_options, timeout=5)
    openssl = managed_process(provider, server_options, timeout=5)

    expected_version = get_expected_s2n_version(protocol, provider)

    for client_results in s2nc.get_results():
        client_results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in client_results.stdout
        assert to_bytes("Cipher negotiated: {}".format(
            cipher.name)) in client_results.stdout

    for server_results in openssl.get_results():
        server_results.assert_success()
        assert random_bytes in server_results.stdout
