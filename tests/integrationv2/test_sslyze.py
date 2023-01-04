import pytest
import sslyze
import abc
from enum import Enum, auto

from configuration import available_ports, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, Cipher, Ciphers, Curves
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import S2N
from utils import get_parameter_name, invalid_test_parameters
from global_flags import get_flag, S2N_PROVIDER_VERSION

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
        "RSA_PSS_2048_SHA256"  # SSLyze errors when given an RSA PSS cert
    }
]

CIPHER_SUITE_SCANS = {
    Protocols.SSLv3.value: sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
    Protocols.TLS10.value: sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
    Protocols.TLS11.value: sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
    Protocols.TLS12.value: sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
    Protocols.TLS13.value: sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES
}


class ScanVerifier:
    __metaclass__ = abc.ABCMeta

    def __init__(self, scan_result, protocol, certificate=None):
        self.scan_result = scan_result
        self.protocol = protocol
        self.certificate = certificate

    @abc.abstractmethod
    def assert_scan_success(self):
        pass


class CipherSuitesVerifier(ScanVerifier):
    def assert_scan_success(self):
        assert self.scan_result.is_tls_version_supported is True

        rejected_ciphers = [
            cipher for rejected_cipher in self.scan_result.rejected_cipher_suites
            if (cipher := Ciphers.from_iana(rejected_cipher.cipher_suite.name))
        ]

        for cipher in rejected_ciphers:
            # If a cipher is rejected, it should be an invalid test parameter in combination with the
            # protocol/provider/cert, otherwise it should have been accepted
            assert invalid_test_parameters(
                protocol=self.protocol,
                provider=S2N,
                certificate=self.certificate,
                cipher=cipher
            )


class EllipticCurveVerifier(ScanVerifier):
    def assert_scan_success(self):
        assert self.scan_result.supports_ecdh_key_exchange is True

        rejected_curves = [
            curve for rejected_curve in self.scan_result.rejected_curves
            if (curve := {
                "X25519": Curves.X25519,
                "prime256v1": Curves.P256,
                "prime384v1": Curves.P384,
                "prime521v1": Curves.P521
            }.get(rejected_curve.name))
        ]

        for curve in rejected_curves:
            # If a curve is rejected, it should be an invalid test parameter in combination with the
            # protocol/provider/cert, otherwise it should have been accepted
            assert invalid_test_parameters(
                protocol=self.protocol,
                provider=S2N,
                certificate=self.certificate,
                curve=curve
            )


class RobotVerifier(ScanVerifier):
    def assert_scan_success(self):
        if self.protocol == Protocols.TLS13:
            assert self.scan_result.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED
        else:
            assert self.scan_result.robot_result == sslyze.RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE


class SessionResumptionVerifier(ScanVerifier):
    def assert_scan_success(self):
        if self.protocol == Protocols.TLS13:
            pass  # SSLyze does not support session resumption scans for tls 1.3
        else:
            assert self.scan_result.tls_ticket_resumption_result == sslyze.TlsResumptionSupportEnum.FULLY_SUPPORTED


class CrimeVerifier(ScanVerifier):
    def assert_scan_success(self):
        assert self.scan_result.supports_compression is False


class EarlyDataVerifier(ScanVerifier):
    def assert_scan_success(self):
        if self.protocol == Protocols.TLS13:
            assert self.scan_result.supports_early_data is True
        else:
            assert self.scan_result.supports_early_data is False


class DowngradePreventionVerifier(ScanVerifier):
    def assert_scan_success(self):
        assert self.scan_result.supports_fallback_scsv is True


class HeartbleedVerifier(ScanVerifier):
    def assert_scan_success(self):
        assert self.scan_result.is_vulnerable_to_heartbleed is False


class CCSInjectionVerifier(ScanVerifier):
    def assert_scan_success(self):
        assert self.scan_result.is_vulnerable_to_ccs_injection is False


class InsecureRenegotiationVerifier(ScanVerifier):
    def assert_scan_success(self):
        assert self.scan_result.is_vulnerable_to_client_renegotiation_dos is False


def validate_scan_result(scan_attempt, protocol, certificate=None):
    assert_scan_attempt_completed(scan_attempt)
    scan_result = scan_attempt.result

    verifier_cls = {
        sslyze.CipherSuitesScanResult:              CipherSuitesVerifier,
        sslyze.SupportedEllipticCurvesScanResult:   EllipticCurveVerifier,
        sslyze.RobotScanResult:                     RobotVerifier,
        sslyze.SessionResumptionSupportScanResult:  SessionResumptionVerifier,
        sslyze.CompressionScanResult:               CrimeVerifier,
        sslyze.EarlyDataScanResult:                 EarlyDataVerifier,
        sslyze.FallbackScsvScanResult:              DowngradePreventionVerifier,
        sslyze.HeartbleedScanResult:                HeartbleedVerifier,
        sslyze.OpenSslCcsInjectionScanResult:       CCSInjectionVerifier,
        sslyze.SessionRenegotiationScanResult:      InsecureRenegotiationVerifier
    }.get(type(scan_result))

    assert verifier_cls is not None, f"unexpected scan: {scan_attempt}"

    verifier = verifier_cls(scan_result, protocol, certificate)
    verifier.assert_scan_success()


def get_scan_attempts(scan_results):
    # scan_results (sslyze.AllScanCommandsAttempts) is an object containing parameters mapped to scan attempts. convert
    # this to a list containing just scan attempts, and then filter out tests that were not scheduled.
    scan_attribute_names = [attr_name for attr_name in dir(
        scan_results) if not attr_name.startswith("__")]
    scan_attempts = [getattr(scan_results, attr_name)
                     for attr_name in scan_attribute_names]
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


def run_sslyze_scan(host, port, scans):
    scan_request = sslyze.ServerScanRequest(
        server_location=sslyze.ServerNetworkLocation(hostname=host, port=port),
        scan_commands=scans
    )
    scanner = sslyze.Scanner(per_server_concurrent_connections_limit=1)
    scanner.queue_scans([scan_request])
    return scanner.get_results()


def invalid_sslyze_scan_parameters(*args, **kwargs):
    scan_command = kwargs["scan_command"]
    protocol = kwargs["protocol"]

    # BUG_IN_SSLYZE error in TLS compression and session renegotiation scans
    # in fips libcryptos when TLS version < 1.3
    if "fips" in get_flag(S2N_PROVIDER_VERSION) and protocol != Protocols.TLS13:
        if scan_command in [
            sslyze.ScanCommand.TLS_COMPRESSION,
            sslyze.ScanCommand.SESSION_RENEGOTIATION
        ]:
            return True
    # BUG_IN_SSLYZE error for session resumption scan with openssl 1.0.2 fips
    if "openssl-1.0.2-fips" in get_flag(S2N_PROVIDER_VERSION):
        if scan_command == sslyze.ScanCommand.SESSION_RESUMPTION:
            return True

    return invalid_test_parameters(*args, **kwargs)


@pytest.mark.uncollect_if(func=invalid_sslyze_scan_parameters)
@pytest.mark.parametrize("protocol", PROTOCOLS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("scan_command", SSLYZE_SCANS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
def test_sslyze_scans(managed_process, protocol, scan_command, provider):
    port = next(available_ports)

    server_options = ProviderOptions(
        mode=S2N.ServerMode,
        host=HOST,
        port=port,
        protocol=protocol,
        extra_flags=["--parallelize"]
    )

    # Test 1.3 exclusively
    if protocol == Protocols.TLS13:
        server_options.cipher = Cipher(
            "test_all_tls13", Protocols.TLS13, False, False, s2n=True)

    if scan_command == sslyze.ScanCommand.SESSION_RESUMPTION:
        server_options.reconnect = True,
        server_options.use_session_ticket = True,

    if scan_command == sslyze.ScanCommand.TLS_1_3_EARLY_DATA:
        server_options.insecure = True
        server_options.use_session_ticket = True
        server_options.extra_flags.extend([
            "--max-early-data", "65535",
            "--https-server"  # Early data scan sends http requests
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


class CertificateScan(Enum):
    CIPHER_SUITE_SCAN = auto()
    ELLIPTIC_CURVE_SCAN = auto()


def invalid_certificate_scans_parameters(*args, **kwargs):
    certificate = kwargs["certificate"]
    certificate_scan = kwargs["certificate_scan"]
    protocol = kwargs["protocol"]

    if certificate_scan == CertificateScan.CIPHER_SUITE_SCAN:
        if "openssl-1.0.2" in get_flag(S2N_PROVIDER_VERSION):
            # SSLyze scan results in rejected ciphers that should have been accepted
            # for TLS 1.2
            if protocol == Protocols.TLS12:
                return True
        if "fips" in get_flag(S2N_PROVIDER_VERSION):
            # BUG_IN_SSLYZE / TLS version supported assertion failures for ECDSA scans
            # in SSLv3 and RSA with TLS version < 1.2 with fips libcryptos
            if "ECDSA" in certificate.name and protocol == Protocols.SSLv3:
                return True
            if "RSA" in certificate.name and protocol in [
                Protocols.SSLv3,
                Protocols.TLS10,
                Protocols.TLS11
            ]:
                return True
    elif certificate_scan == CertificateScan.ELLIPTIC_CURVE_SCAN:
        # SSLyze curves scan errors when given ECDSA certs
        if "ECDSA" in certificate.name:
            return True

        # SSLyze curves scan fails to validate with openssl 1.0.2 fips
        if "openssl-1.0.2-fips" in get_flag(S2N_PROVIDER_VERSION):
            return True

    return invalid_test_parameters(*args, **kwargs)


@pytest.mark.uncollect_if(func=invalid_certificate_scans_parameters)
@pytest.mark.parametrize("protocol", PROTOCOLS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", CERTS_TO_TEST, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("certificate_scan", [
    CertificateScan.CIPHER_SUITE_SCAN,
    CertificateScan.ELLIPTIC_CURVE_SCAN
], ids=lambda certificate_scan: certificate_scan.name)
def test_sslyze_certificate_scans(managed_process, protocol, certificate, provider, certificate_scan):
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

    scan = {
        CertificateScan.CIPHER_SUITE_SCAN: CIPHER_SUITE_SCANS.get(protocol.value),
        CertificateScan.ELLIPTIC_CURVE_SCAN: sslyze.ScanCommand.ELLIPTIC_CURVES
    }.get(certificate_scan)

    scan_attempt_results = run_sslyze_scan(HOST, port, [scan])

    for scan_attempt_result in scan_attempt_results:
        assert_scan_result_completed(scan_attempt_result)

        scan_result = scan_attempt_result.scan_result
        scan_attempts = get_scan_attempts(scan_result)
        for scan_attempt in scan_attempts:
            validate_scan_result(scan_attempt, protocol, certificate)

    server.kill()
