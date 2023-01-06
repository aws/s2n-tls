import copy
import math
import pytest

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, MINIMAL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes
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

# arbitrarily large payload size
PAYLOAD_SIZE = 1024


def get_record_header(payload_size: int) -> str:
    # In the TLS record header, the last two bytes are reserved for length
    hex_string = "{:04x}".format(payload_size)
    first_byte, second_byte = hex_string[:2], hex_string[2:]
    return "17 03 03 {} {}".format(first_byte, second_byte)


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
# only tls 1.3 supports record padding
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("padding_size", PADDING_SIZES, ids=get_parameter_name)
def test_s2n_13_server_handles_padded_records(managed_process, cipher, provider, curve, protocol, certificate,
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

    expected_total_length = None
    if padding_size == 0:
        # if padding size is zero, then the expected total length is
        # equal to the payload size + 16 bytes of AEAD + 1 byte for content type
        expected_total_length = PAYLOAD_SIZE + 16 + 1
    else:
        expected_total_length = padding_size + 16

    expected_record_header = get_record_header(expected_total_length)

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
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
# only tls 1.3 supports record padding
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", MINIMAL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("padding_size", PADDING_SIZES, ids=get_parameter_name)
def test_s2n_13_client_handles_padded_records(managed_process, cipher, provider, curve, protocol, certificate,
                                              padding_size):
    port = next(available_ports)

    random_bytes = data_bytes(PAYLOAD_SIZE)
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
        # use -rev s.t the openssl server echoes back the s2nc payload (but reversed)
        extra_flags=['-num_tickets', 0,
                     '-record_padding', padding_size, '-rev']
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

    expected_total_length = None
    if padding_size == 0:
        # if there is no padding, then the openssl server payload size must be the original payload size
        # + 16 bytes of aead tag + 1 byte of content type + 1 byte for the new-line char sent by s2n
        expected_total_length = PAYLOAD_SIZE + 16 + 1 + 1
    elif padding_size < PAYLOAD_SIZE:
        # if the padding size is smaller than the payload size then openssl will attempt to pad to
        # the next largest multiple of padding_size + 16 bytes of aead tag
        rounded = math.ceil(PAYLOAD_SIZE / padding_size)
        expected_total_length = (padding_size * rounded) + 16
    else:
        # else the padding size is larger than the payload size. The output payload size must be
        # the padding size + 16 bytes of aead tag.
        expected_total_length = padding_size + 16

    expected_record_header = get_record_header(expected_total_length)

    for server_results in openssl.get_results():
        server_results.assert_success()
        assert to_bytes(expected_record_header) in server_results.stdout
