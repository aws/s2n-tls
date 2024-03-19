import platform
import pytest

ALL = set(["aarch64", "x86_64"])


def pytest_runtest_setup(item):
    supported_platforms = ALL.intersection(mark.name for mark in item.iter_markers())
    plat = platform.machine()
    if supported_platforms and plat not in supported_platforms:
        pytest.skip("platform specific test; not running on {}".format(plat))
