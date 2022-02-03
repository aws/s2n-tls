import pytest

from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum
from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin, HeartbleedScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerRejectedConnection

from configuration import available_ports
from common import ProviderOptions, Protocols, Cipher
from fixtures import managed_process
from providers import S2N
from utils import get_parameter_name


def validate_plugin_result(plugin_result):
    scan_passed = {
        RobotScanCommand: lambda result: result.robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE
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

    plugin = RobotPlugin()
    plugin_result = plugin.process_task(server_info, RobotScanCommand())

    validate_plugin_result(plugin_result)

