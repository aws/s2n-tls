import pytest
import sslyze

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, Cipher, Ciphers, Certificates, Curves
from fixtures import managed_process
from providers import S2N
from utils import get_parameter_name, invalid_test_parameters

HOST = "127.0.0.1"

PROTOCOLS_TO_TEST = [
    Protocols.SSLv3,
    Protocols.TLS10,
    Protocols.TLS11,
    Protocols.TLS12,
    Protocols.TLS13
]

SSLYZE_SCANS_TO_TEST = {
    sslyze.ScanCommand.ROBOT,
    sslyze.ScanCommand.SESSION_RESUMPTION,
    sslyze.ScanCommand.TLS_COMPRESSION,
    sslyze.ScanCommand.TLS_1_3_EARLY_DATA,
    sslyze.ScanCommand.TLS_FALLBACK_SCSV,
    sslyze.ScanCommand.HEARTBLEED,
    sslyze.ScanCommand.OPENSSL_CCS_INJECTION,
    sslyze.ScanCommand.SESSION_RENEGOTIATION
}

CERTS_TO_TEST = [
    cert for cert in ALL_TEST_CERTS if cert.name not in {
        "RSA_PSS_2048_SHA256"  # sslyze doesn't like this cert
    }
]

CIPHER_SUITE_SCANS = {
    Protocols.SSLv3.value: sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
    Protocols.TLS10.value: sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
    Protocols.TLS11.value: sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
    Protocols.TLS12.value: sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
    Protocols.TLS13.value: sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES
}


def get_scan_attempts(scan_results):
    scan_attribute_names = [attr_name for attr_name in dir(scan_results) if not attr_name.startswith("__")]
    scan_attempts = [getattr(scan_results, attr_name) for attr_name in scan_attribute_names]
    scan_attempts = [
        scan_attempt for scan_attempt in scan_attempts
        if scan_attempt.status != sslyze.ScanCommandAttemptStatusEnum.NOT_SCHEDULED
    ]
    return scan_attempts


def assert_scan_result_completed(scan_result):
    def get_connectivity_error_str(tb):
        return "\n".join(tb.stack.format())

    assert scan_result.connectivity_status == sslyze.ServerConnectivityStatusEnum.COMPLETED, \
        f"sslyze could not connect to server: {get_connectivity_error_str(scan_result.connectivity_error_trace)}"


def assert_scan_attempt_completed(scan_attempt):
    assert scan_attempt.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED, \
        f"scan attempt ({scan_attempt}) failed: {scan_attempt.status}"


def validate_scan_result(scan_attempt, protocol):
    assert_scan_attempt_completed(scan_attempt)

    scan_result = scan_attempt.result
    scan_passed = {
        sslyze.RobotScanResult: {
            Protocols.TLS13.value:
                lambda scan:
                    scan.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED
        }.get(
            protocol.value,
            lambda scan:
                scan.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE
        ),
        sslyze.SessionResumptionSupportScanResult: {
            Protocols.TLS13.value: lambda scan: True  # ignore session resumption scan result for tls13
        }.get(
            protocol.value,
            lambda scan:
                scan.tls_ticket_resumption_result == sslyze.TlsResumptionSupportEnum.FULLY_SUPPORTED
        ),
        sslyze.CompressionScanResult:
            lambda scan: scan.supports_compression is False,
        sslyze.EarlyDataScanResult: {
            Protocols.TLS13.value:
                lambda scan: scan.supports_early_data is True
        }.get(
            protocol.value,
            lambda scan: scan.supports_early_data is False
        ),
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


def run_sslyze_scan(host, port, scans):
    scan_request = sslyze.ServerScanRequest(
        server_location=sslyze.ServerNetworkLocation(hostname=host, port=port),
        scan_commands=scans
    )
    scanner = sslyze.Scanner(per_server_concurrent_connections_limit=1)
    scanner.queue_scans([scan_request])
    return scanner.get_results()


@pytest.mark.parametrize("protocol", PROTOCOLS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("scan_command", SSLYZE_SCANS_TO_TEST, ids=get_parameter_name)
def test_sslyze_scans(managed_process, protocol, scan_command):
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

    if scan_command == sslyze.ScanCommand.SESSION_RESUMPTION:
        server_options.reconnect = True,
        server_options.use_session_ticket = True,

    if scan_command == sslyze.ScanCommand.TLS_1_3_EARLY_DATA:
        server_options.insecure = True
        server_options.use_session_ticket = True
        server_options.extra_flags.extend([
            "--max-early-data", "65535",
            "--https-server"  # early data scan sends http requests
        ])

    server = managed_process(S2N, server_options, timeout=30)

    scan_results = run_sslyze_scan(HOST, port, [scan_command])

    for result in scan_results:
        assert_scan_result_completed(result)

        scan_results = result.scan_result
        scan_attempts = get_scan_attempts(scan_results)
        for scan_attempt in scan_attempts:
            validate_scan_result(scan_attempt, protocol)

    server.kill()


def validate_certificate_scan_result(scan_attempt, protocol, certificate):
    assert_scan_attempt_completed(scan_attempt)
    result = scan_attempt.result

    def validate_cipher_scan(result, protocol, certificate):
        assert result.is_tls_version_supported is True

        rejected_ciphers = [
            cipher for rejected_cipher in result.rejected_cipher_suites
            if (cipher := Ciphers.from_iana(rejected_cipher.cipher_suite.name))
        ]

        for cipher in rejected_ciphers:
            # if a cipher is rejected, it should be an invalid test parameter in combination with the
            # protocol/provider/cert
            assert invalid_test_parameters(
                protocol=protocol,
                provider=S2N,
                certificate=certificate,
                cipher=cipher
            )

    def validate_curves_scan(result, protocol, certificate):
        assert result.supports_ecdh_key_exchange is True

        rejected_curves = [
            curve for rejected_curve in result.rejected_curves
            if (curve := {
                "X25519": Curves.X25519,
                "prime256v1": Curves.P256,
                "prime384v1": Curves.P384,
                "prime521v1": Curves.P521
            }.get(rejected_curve.name))
        ]

        for curve in rejected_curves:
            assert invalid_test_parameters(
                protocol=protocol,
                provider=S2N,
                certificate=certificate,
                curve=curve
            )

    {
        sslyze.CipherSuitesScanResult: validate_cipher_scan,
        sslyze.SupportedEllipticCurvesScanResult: validate_curves_scan,
    }.get(type(result))(result, protocol, certificate)


@pytest.mark.parametrize("protocol", PROTOCOLS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTS_TO_TEST, ids=get_parameter_name)
def test_sslyze_certificate_scans(managed_process, protocol, certificate):
    port = next(available_ports)

    server_options = ProviderOptions(
        mode=S2N.ServerMode,
        host=HOST,
        port=port,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert,
        insecure=True,
        extra_flags=["--parallelize"]
    )
    server = managed_process(S2N, server_options, timeout=30)

    scans = [CIPHER_SUITE_SCANS.get(protocol.value)]

    # sslyze doesn't like ECDSA certs for curve scan
    if "ECDSA" not in certificate.name:
        scans.append(sslyze.ScanCommand.ELLIPTIC_CURVES)

    scan_attempt_results = run_sslyze_scan(HOST, port, scans)

    for scan_attempt_result in scan_attempt_results:
        assert_scan_result_completed(scan_attempt_result)

        scan_result = scan_attempt_result.scan_result
        scan_attempts = get_scan_attempts(scan_result)

        for scan_attempt in scan_attempts:
            validate_certificate_scan_result(scan_attempt, protocol, certificate)

    server.kill()
