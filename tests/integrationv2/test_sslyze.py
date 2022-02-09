import pytest
import sslyze

from configuration import available_ports
from common import ProviderOptions, Protocols, Cipher
from fixtures import managed_process
from providers import S2N
from utils import get_parameter_name

HOST = "127.0.0.1"

PROTOCOLS_TO_TEST = [
    Protocols.TLS10,
    Protocols.TLS11,
    Protocols.TLS12,
    Protocols.TLS13
]

SSLYZE_SCANS_TO_TEST = {
    sslyze.ScanCommand.ROBOT,
    sslyze.ScanCommand.TLS_COMPRESSION,
    sslyze.ScanCommand.TLS_FALLBACK_SCSV,
    sslyze.ScanCommand.HEARTBLEED,
    sslyze.ScanCommand.OPENSSL_CCS_INJECTION,
    sslyze.ScanCommand.SESSION_RENEGOTIATION
}


def get_scan_attempts(scan_results):
    scan_attribute_names = [attr_name for attr_name in dir(scan_results) if not attr_name.startswith("__")]
    scan_attempts = [getattr(scan_results, attr_name) for attr_name in scan_attribute_names]
    return scan_attempts


def validate_scan_result(scan_attempt, protocol):
    assert scan_attempt.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED, \
        f"scan attempt ({scan_attempt}) failed: {scan_attempt.status}"

    scan_result = scan_attempt.result
    scan_passed = {
        sslyze.RobotScanResult: {
            Protocols.TLS13.value: lambda scan:
                scan.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED
        }.get(
            protocol.value,
            lambda scan:
                scan.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE
        ),
        sslyze.CompressionScanResult:
            lambda scan: scan.supports_compression is False,
        sslyze.FallbackScsvScanResult:
            lambda scan: scan.supports_fallback_scsv is True,
        sslyze.HeartbleedScanResult:
            lambda scan: scan.is_vulnerable_to_heartbleed is False,
        sslyze.OpenSslCcsInjectionScanResult:
            lambda scan: scan.is_vulnerable_to_ccs_injection is False,
        sslyze.SessionRenegotiationScanResult:
            lambda scan: scan.is_vulnerable_to_client_renegotiation_dos is False
    }.get(type(scan_result))

    assert scan_passed is not None, f"unexpected scan: {scan_attempt}"
    assert scan_passed(scan_result), f"unexpected scan result: {scan_result}"


@pytest.mark.parametrize("protocol", PROTOCOLS_TO_TEST, ids=get_parameter_name)
def test_sslyze_scans(managed_process, protocol):
    port = next(available_ports)

    server_options = ProviderOptions(
        mode=S2N.ServerMode,
        host=HOST,
        port=port,
        protocol=protocol,
        extra_flags=["--parallelize"]
    )

    # test 1.3 exclusively
    if protocol == Protocols.TLS13:
        server_options.cipher = Cipher("test_all_tls13", Protocols.TLS13, False, False, s2n=True)

    server = managed_process(S2N, server_options, timeout=30)

    scan_request = sslyze.ServerScanRequest(
        server_location=sslyze.ServerNetworkLocation(hostname=HOST, port=port),
        scan_commands=SSLYZE_SCANS_TO_TEST
    )
    scanner = sslyze.Scanner(per_server_concurrent_connections_limit=1)
    scanner.queue_scans([scan_request])

    for result in scanner.get_results():
        def get_connectivity_error_str(tb):
            return "\n".join(tb.stack.format())

        assert result.connectivity_status == sslyze.ServerConnectivityStatusEnum.COMPLETED, \
            f"sslyze could not connect to server: {get_connectivity_error_str(result.connectivity_error_trace)}"

        scan_results = result.scan_result
        scan_attempts = get_scan_attempts(scan_results)
        for scan_attempt in scan_attempts:
            if scan_attempt.status == sslyze.ScanCommandAttemptStatusEnum.NOT_SCHEDULED:
                continue

            validate_scan_result(scan_attempt, protocol)

    server.kill()
