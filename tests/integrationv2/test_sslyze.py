import pytest

from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvPlugin, FallbackScsvScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin, HeartbleedScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin, OpenSslCcsInjectionScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationPlugin, SessionRenegotiationScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerRejectedConnection

from configuration import available_ports
from common import ProviderOptions, Protocols, Cipher
from fixtures import managed_process
from providers import S2N
from utils import get_parameter_name


SSLYZE_PLUGINS_TO_TEST = [
    (RobotPlugin(), RobotScanCommand()),
    (FallbackScsvPlugin(), FallbackScsvScanCommand()),
    (HeartbleedPlugin(), HeartbleedScanCommand()),
    (OpenSslCcsInjectionPlugin(), OpenSslCcsInjectionScanCommand()),
    (SessionRenegotiationPlugin(), SessionRenegotiationScanCommand())
]


def validate_plugin_result(plugin_result):
    scan_passed = {
        RobotScanCommand:
            lambda result: result.robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE,
        FallbackScsvScanCommand:
            lambda result: result.supports_fallback_scsv is True,
        HeartbleedScanCommand:
            lambda result: result.is_vulnerable_to_heartbleed is False,
        OpenSslCcsInjectionScanCommand:
            lambda result: result.is_vulnerable_to_ccs_injection is False,
        SessionRenegotiationScanCommand:
            lambda result: result.supports_secure_renegotiation is True
    }.get(plugin_result.scan_command.__class__)

    assert scan_passed is not None, f"unexpected scan command: {plugin_result.scan_command.__class__}"
    assert scan_passed(plugin_result), f"unexpected plugin result: {plugin_result}"


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

    # test 1.3 exclusively
    if protocol == Protocols.TLS13:
        server_options.cipher = Cipher("test_all_tls13", Protocols.TLS13, False, False, s2n=True)

    server = managed_process(S2N, server_options, timeout=30)

    server_test = ServerConnectivityTester(hostname="127.0.0.1", port=port)
    try:
        server_info = server_test.perform()
    except ServerRejectedConnection:
        assert False, "sslyze could not connect to server"

    for plugin, scan_command in SSLYZE_PLUGINS_TO_TEST:
        plugin_result = plugin.process_task(server_info, scan_command)
        validate_plugin_result(plugin_result)

