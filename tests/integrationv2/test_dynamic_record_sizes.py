import copy
import os
import pytest
import subprocess
import time

from configuration import available_ports, CIPHERSUITES, CURVES, PROVIDERS
from common import ProviderOptions, data_bytes
from fixtures import managed_process, custom_mtu
from providers import S2N, OpenSSL, Tcpdump


def find_fragmented_packet(results):
    """
    This function searches Tcpdump's standard output and looks for packets
    that have a length larger than the MTU(hardcoded to 1500) of the device.
    """
    for line in results.decode('utf-8').split('\n'):
        pieces = line.split(' ')
        if len(pieces) < 2:
            continue

        if pieces[-2] == 'length':
            if int(pieces[-1]) > 1500:
                return True

    return False


@pytest.mark.parametrize("cipher", CIPHERSUITES)
@pytest.mark.parametrize("curve", CURVES)
def test_s2n_client_dynamic_record(custom_mtu, managed_process, cipher, curve):
    host = "localhost"
    port = next(available_ports)

    # 16384 bytes is enough to reliably get a packet that will exceed the MTU
    bytes_to_send = data_bytes(16384)
    client_options = ProviderOptions(
        mode="client",
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=bytes_to_send,
        insecure=True,
        tls13=True)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = "server"
    server_options.key = "../pems/ecdsa_p384_pkcs1_key.pem"
    server_options.cert = "../pems/ecdsa_p384_pkcs1_cert.pem"

    # This test shouldn't last longer than 5 seconds, even though
    # Tcpdump tends to take a second to startup.
    tcpdump = managed_process(Tcpdump, client_options, timeout=5)
    server = managed_process(OpenSSL, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b"Actual protocol version: 34" in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    # The Tcpdump provider only captures 12 packets. This is enough
    # to detect a packet larger than the MTU, but less than the
    # total packets sent. This is important because it lets Tcpdump
    # exit cleanly, which means all the output is available for us
    # to examine.
    for results in tcpdump.get_results():
        assert results.exit_code == 0
        assert find_fragmented_packet(results.stdout) is True
