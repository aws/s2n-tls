import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS
from common import ProviderOptions, data_bytes
from fixtures import custom_mtu, managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, Tcpdump
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes


def find_fragmented_packet(results):
    """
    This function searches Tcpdump's standard output and looks for packets
    that have a length larger than the MTU(hardcoded to 1500) of the device.

    When traffic goes over a known port, such as 8080, the protocol is appended
    to the output line. This happens even when using `-nn` on the command line.
    That is why we need two ways to detect the length of the packet.
    """
    for line in results.decode('utf-8').split('\n'):
        pieces = line.split(' ')
        if len(pieces) < 3:
            continue

        packet_len = 0
        if pieces[-2] == 'length':
            packet_len = int(pieces[-1])
        elif pieces[-3] == 'length':
            # In this case the length has a colon `1234:`, so we must trim it.
            packet_len = int(pieces[-2][:-1])

        if packet_len > 1500:
            return True

    return False


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_s2n_client_dynamic_record(custom_mtu, managed_process, cipher, curve, provider, other_provider, protocol,
                                   certificate):
    port = next(available_ports)

    # 16384 bytes is enough to reliably get a packet that will exceed the MTU
    bytes_to_send = data_bytes(16384)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=bytes_to_send,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    expected_version = get_expected_s2n_version(protocol, provider)

    # This test shouldn't last longer than 5 seconds, even though
    # Tcpdump tends to take a second to startup.
    tcpdump = managed_process(Tcpdump, client_options, timeout=5)
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in results.stdout

    for results in server.get_results():
        results.assert_success()

    # The Tcpdump provider only captures 12 packets. This is enough
    # to detect a packet larger than the MTU, but less than the
    # total packets sent. This is important because it lets Tcpdump
    # exit cleanly, which means all the output is available for us
    # to examine.
    for results in tcpdump.get_results():
        assert results.exit_code == 0
        assert find_fragmented_packet(results.stdout) is True
