import time
import pytest
import threading
from processes import ManagedProcess
from providers import Provider
from common import ProviderOptions


@pytest.fixture
def managed_process():
    """
    Generic process manager. This could be used to launch any process as a background
    task and cleanup when finished.
    """
    processes = []

    def _fn(provider_class: Provider, options: ProviderOptions, timeout=5):
        provider = provider_class(options)
        cmd_line = provider.get_cmd_line()
        p = ManagedProcess(cmd_line, provider.set_provider_ready, timeout)

        processes.append(p)
        with p.ready_condition:
            p.start()
            with provider._provider_ready_condition:
                provider._provider_ready_condition.wait_for(provider.is_provider_ready, 1)
        return p

    try:
        yield _fn
    except Exception as e:
        print("Gracefully handling exception")
    finally:
        for p in processes:
            p.join()
