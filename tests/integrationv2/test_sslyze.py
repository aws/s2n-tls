from enum import Enum

import pytest
import sslyze

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS, TLS13_CIPHERS
from common import ProviderOptions, Protocols, Curves, data_bytes
from fixtures import managed_process
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name, to_bytes

def validate_scan_result(scan_attempt, protocol):
    assert scan_attempt.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED

    scan_result = scan_attempt.result
    scan_passed = {
        sslyze.RobotScanResult: {
            Protocols.TLS12.value: lambda scan:
                scan.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE,
            Protocols.TLS13.value: lambda scan:
                scan.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED
        }.get(protocol.value)
    }.get(type(scan_result))

    assert scan_passed(scan_result)


#@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12], ids=get_parameter_name)
def test_sslyze_scans(managed_process):
    protocol = Protocols.TLS12
    port = next(available_ports)

    server_options = ProviderOptions(
        mode=S2N.ServerMode,
        host="127.0.0.1",
        port=port,
        protocol=protocol,
        extra_flags=["--parallelize"]
    )
    server = managed_process(S2N, server_options, timeout=30)

    scan_request = sslyze.ServerScanRequest(
        server_location=sslyze.ServerNetworkLocation(hostname="127.0.0.1", port=port)
    )
    scanner = sslyze.Scanner(per_server_concurrent_connections_limit=1)
    scanner.queue_scans([scan_request])

    for result in scanner.get_results():
        print(result.connectivity_status)

        scan_result = result.scan_result
        print(scan_result.robot)
        validate_scan_result(scan_result.robot, protocol)


def test_func():
    print("test!!")
    assert 1 == 1
