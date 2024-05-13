import pytest
from os import getenv
from global_flags import set_flag, S2N_PROVIDER_VERSION, S2N_FIPS_MODE, S2N_NO_PQ, S2N_USE_CRITERION
from platform import machine

ALLPLATFORMS = set(["aarch64", "x86_64"])
FIXNIXMARK = set(["fix4nix"])


def pytest_addoption(parser):
    parser.addoption("--provider-version", action="store", dest="provider-version",
                     default=None, type=str, help="Set the version of the TLS provider")
    parser.addoption("--fips-mode", action="store", dest="fips-mode",
                     default=False, type=int, help="S2N is running in FIPS mode")
    parser.addoption("--no-pq", action="store", dest="no-pq",
                     default=False, type=int, help="Turn off PQ support")
    parser.addoption("--provider-criterion", action="store", dest="provider-criterion",
                     default="off", type=str, choices=['off', 'baseline', 'delta'], help="Use Criterion provider in one of 3 modes: [off,baseline,delta]")


def pytest_configure(config):
    """
    pytest hook that adds the function to deselect tests if the parameters
    don't makes sense.
    """
    no_pq = config.getoption('no-pq', 0)
    fips_mode = config.getoption('fips-mode', 0)
    if no_pq == 1:
        set_flag(S2N_NO_PQ, True)
    if fips_mode == 1:
        set_flag(S2N_FIPS_MODE, True)

    set_flag(S2N_PROVIDER_VERSION, config.getoption('provider-version', None))
    set_flag(S2N_USE_CRITERION, config.getoption('provider-criterion', "off"))


def pytest_collection_modifyitems(config, items):
    """
    pytest hook to modify the test arguments to call the uncollect function.
    """
    removed = []
    kept = []
    for item in items:
        m = item.get_closest_marker('uncollect_if')
        if m:
            func = m.kwargs['func']
            if func(**item.callspec.params):
                removed.append(item)
                continue
        kept.append(item)
    if removed:
        config.hook.pytest_deselected(items=removed)
        items[:] = kept


def pytest_runtest_setup(item: pytest.Item) -> None:
    """
    Automatically skip specific tests, using marks.
    e.g. at the beginning of a test only to be run on x86:
    @pytest.mark.x86_64

    or to skip if we're in a Nix environment:
    @pytest.mark.fix4nix
    """
    # Find the intersection of all pytest.marks and ALLPLATFORMS.
    # By default, with no platform marks, this set will be empty.
    marked_platform = ALLPLATFORMS.intersection(mark.name for mark in item.iter_markers())
    # Get the current runtime platform.
    platform = machine()
    # Skip this test if a platform mark was defined but doesn't match the current platform.
    if platform is not None and marked_platform and platform not in marked_platform:
        pytest.skip(f"Platform specific test; not running on {platform}")

    # Look for a not-in-nix mark, and check for a Nix defined env. var to skip the test.
    not_nix_mark = FIXNIXMARK.intersection(mark.name for mark in item.iter_markers())
    if getenv("IN_NIX_SHELL", None) and not_nix_mark:
        pytest.skip(f"Nix detected; skipping this test")
