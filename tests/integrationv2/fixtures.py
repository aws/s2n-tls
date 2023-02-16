import os
import pytest
import subprocess

from global_flags import get_flag, is_criterion_on, S2N_USE_CRITERION
from processes import ManagedProcess
from providers import Provider, CriterionS2N, S2N

from common import ProviderOptions


@pytest.fixture
def managed_process():
    """
    Generic process manager. This could be used to launch any process as a background
    task and cleanup when finished.

    The reason a fixture is used, instead of creating a ManagedProcess() directly
    from the test, is to control the life of the process. Using the fixture
    allows cleanup after a test, even if a failure occurred.
    """
    processes = []

    def _fn(provider_class: Provider, options: ProviderOptions, timeout=5, send_marker=None, close_marker=None,
            expect_stderr=None, kill_marker=None, send_with_newline=None):
        if provider_class == S2N and is_criterion_on():
            provider_class = CriterionS2N
            # This comes from the number of iterations specific in the rust benchmark handler(s).
            # currently set at 10 iterations, so give us 10x more time.
            timeout = timeout * 10
        provider = provider_class(options)
        cmd_line = provider.get_cmd_line()
        # The process will default to send markers in the providers.py file
        # if not specified by a test.
        if send_marker is not None:
            provider.ready_to_send_input_marker = send_marker
        if expect_stderr is None:
            expect_stderr = provider.expect_stderr
        if send_with_newline is None:
            send_with_newline = provider.send_with_newline
        p = ManagedProcess(
            cmd_line,
            provider.set_provider_ready,
            wait_for_marker=provider.ready_to_test_marker,
            send_marker_list=provider.ready_to_send_input_marker,
            close_marker=close_marker,
            data_source=options.data_to_send,
            timeout=timeout,
            env_overrides=options.env_overrides,
            expect_stderr=expect_stderr,
            kill_marker=kill_marker,
            send_with_newline=send_with_newline
        )

        processes.append(p)
        with p.ready_condition:
            p.start()
            with provider._provider_ready_condition:
                # Don't continue processing until the provider has indicated it is ready.
                provider._provider_ready_condition.wait_for(
                    provider.is_provider_ready, timeout)
        return p

    try:
        yield _fn
    except Exception as e:
        # The ManagedProcess already prints information to stdout, so there
        # is nothing to capture here.
        pass
    finally:
        # Whether the processes succeeded or not, clean then up.
        for p in processes:
            p.join()


def _swap_mtu(device, new_mtu):
    """
    Swap the device's current MTU for the requested MTU.
    Return the original MTU so it can be reset later.
    """
    cmd = ["ip", "link", "show", device]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    mtu = 65536
    for line in p.stdout.readlines():
        s = line.decode("utf-8")
        pieces = s.split(' ')
        if len(pieces) >= 4 and pieces[3] == 'mtu':
            mtu = int(pieces[4])

    p.wait()

    subprocess.call(["ip", "link", "set", device, "mtu", str(new_mtu)])

    return int(mtu)


@pytest.fixture(scope='module')
def custom_mtu():
    """
    This fixture will swap the loopback's MTU from the default
    to 1500, which is more reasonable for a network device.
    Using a fixture allows us to reset the MTU even if the test
    fails.

    These values are all hardcoded because they are only used
    from a single test. This simplifies the use of the fixture.
    """
    if os.geteuid() != 0:
        pytest.skip("Test needs root privileges to modify lo MTU")

    original_mtu = _swap_mtu('lo', 1500)
    yield
    _swap_mtu('lo', original_mtu)
