import copy
import pytest
import math
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

# regex that matches server/client 'write to' with the TLS header
OPENSSL_WRITE_TO_REGEX = r"write to [\w >\(\)\[\]=]*\\n0000 - 17 03 03 [0-9A-Fa-f]{2} [0-9A-Fa-f]{2}"


def to_formatted_hex(payload_size: int) -> str:
    # In the TLS record header, the last two bytes are reserved for length
    hex_string = "{:04x}".format(payload_size)
    first_byte, second_byte = hex_string[:2], hex_string[2:]
    return "{} {}".format(first_byte, second_byte)


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
    # Communication Timeline
    # Client [OpenSSL]                       | Server [S2N]
    # Handshake                              | Handshake
    # Send padded data                       | Receive padded data
    # Send padded close connection           | Close
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

        # find all occurrences of openssl writing to server
        all_occurrences = re.findall(
            OPENSSL_WRITE_TO_REGEX, str(client_results.stdout))

        # In openssl, the close connection record will always be less than the test's minimum
        # padding size of 250 bytes. This means that the close connection record will always be padded
        # to padding_size + 16 bytes. However, the actual application record may not be less than the
        # padding size; in this case openssl will pad the record to the nearest multiple of the padding size
        nearest = math.ceil(PAYLOAD_SIZE / padding_size)
        if nearest == 1:
            # the payload_size must be l.t.e the padding size. This means every sent application record
            # including the close connection record is padded to padding_size + 16 bytes
            expected_size = to_formatted_hex(padding_size + 16)
            for occurrence in all_occurrences:
                actual_size = occurrence[-5:]
                assert actual_size == expected_size
        else:
            # else, the payload_size is g.t the padding size. This means we have two different expected
            # application record sizes.
            number_of_close_connection_records = 0
            number_of_application_records = 0

            # in openssl, the record is padded to the next largest multiple of the padding size
            # notice that if the payload_size is less than the padding size we get the expected
            # payload_size + 16 bytes
            nearest_record_size = nearest * padding_size + 16
            expected_application_record_size = to_formatted_hex(
                nearest_record_size)

            # close connection record must be padded up to padding_size + 16 bytes
            expected_close_connection_record_size = to_formatted_hex(
                padding_size + 16)
            for occurrence in all_occurrences:
                # The last five characters in the matched occurrence gives the record size
                actual_size = occurrence[-5:]
                if actual_size == expected_application_record_size:
                    number_of_application_records += 1
                elif actual_size == expected_close_connection_record_size:
                    number_of_close_connection_records += 1
                else:
                    # all sent records must be padded to one of the expected sizes
                    assert False

            assert number_of_application_records == 1
            assert number_of_close_connection_records == 1

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
def test_s2n_client_handles_padded_records(managed_process, cipher, provider, curve, protocol, certificate,
                                           padding_size):
    # Communication Timeline
    # Client [S2N]                                 | Server [OpenSSL]
    # Handshake                                    | Padded handshake (sent padded NUMBER_OF_SESSION_TICKETS session tickets)
    # Send data                                    | Receive data
    # Receive padded data                          | Send padded data on send_marker client's sent data
    # Close on close_marker server's padded data   | Close
    NUMBER_OF_SESSION_TICKETS = 3
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
        extra_flags=[
            '-record_padding', padding_size, '-num_tickets', NUMBER_OF_SESSION_TICKETS]
    )

    client_options = copy.copy(server_options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = None
    client_options.data_to_send = client_random_bytes

    # s2nc will wait until it has received the server's response before closing
    s2nc = managed_process(S2N, client_options, timeout=5,
                           close_marker=str(server_random_bytes)[2:-1])

    # openssl will send it's response after it has received s2nc's record
    openssl = managed_process(provider, server_options,
                              timeout=5, send_marker=str(client_random_bytes)[2:-1])

    expected_version = get_expected_s2n_version(protocol, provider)
    for client_results in s2nc.get_results():
        client_results.assert_success()
        # assert that the client has received server's application payload
        assert server_random_bytes in client_results.stdout
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in client_results.stdout
        assert to_bytes("Cipher negotiated: {}".format(
            cipher.name)) in client_results.stdout

    # In openssl, the session ticket records will always be less than the test's minimum
    # padding size of 250 bytes. This means that the session ticket record will always be padded
    # to padding_size + 16 bytes. However, the actual application record may not be less than the
    # padding size; in this case openssl will pad the record to the nearest multiple of the padding size
    for server_results in openssl.get_results():
        server_results.assert_success()
        all_occurrences = re.findall(
            OPENSSL_WRITE_TO_REGEX, str(server_results.stdout))
        nearest = math.ceil(PAYLOAD_SIZE / padding_size)
        if nearest == 1:
            # the payload_size must be l.t.e the padding size. This means every sent application record
            # including the sent session tickets are padded to padding_size + 16 bytes
            expected_size = to_formatted_hex(padding_size + 16)
            for occurrence in all_occurrences:
                actual_size = occurrence[-5:]
                assert actual_size == expected_size
        else:
            # else, the payload_size is g.t the padding size. This means we have two
            # different expected application record sizes.
            actual_number_of_session_tickets_sent = 0
            actual_number_of_application_records_sent = 0

            # in openssl, session tickets are always padded to the padding size
            expected_session_ticket_record_size = to_formatted_hex(
                padding_size + 16)

            # in openssl, the record is padded to the next largest multiple of the padding size
            # notice that if the payload_size is less than the padding size we get the expected
            # payload_size + 16 bytes
            nearest_record_size = nearest * padding_size + 16
            expected_application_record_size = to_formatted_hex(
                nearest_record_size)

            for occurrence in all_occurrences:
                # The last five characters in the matched occurrence gives the record size
                actual_size = occurrence[-5:]
                if actual_size == expected_session_ticket_record_size:
                    actual_number_of_session_tickets_sent += 1
                elif actual_size == expected_application_record_size:
                    actual_number_of_application_records_sent += 1
                else:
                    # all sent records must be padded to one of the expected sizes
                    assert False

            assert actual_number_of_session_tickets_sent == NUMBER_OF_SESSION_TICKETS
            assert actual_number_of_application_records_sent == 1
