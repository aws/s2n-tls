# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
import sys
import pytest
from global_flags import set_flag, S2N_PROVIDER_VERSION, S2N_FIPS_MODE
from providers import S2N, JavaSSL

PATH_CONFIGURATION_KEY = pytest.StashKey()


def path_configuration():
    """
    1. determine available providers
    2. modify PATH to make the providers available

    Currently only supports s2nc/s2nd and the Java SSL client.
    """
    providers = set()

    # s2n-tls MUST be available, and we expect it to be in
    # <git_root>/build/bin
    expected_location = os.path.abspath("../../build/bin")
    for binary in ["s2nd", "s2nc"]:
        bin_path = f"{expected_location}/{binary}"
        if not os.path.exists(bin_path):
            pytest.fail(f"unable to locate {binary}")
    os.environ['PATH'] += os.pathsep + expected_location
    providers.add(S2N)

    if os.path.exists("./bin/SSLSocketClient.class"):
        providers.add(JavaSSL)

    return providers


def pytest_addoption(parser: pytest.Parser):
    parser.addoption("--provider-version", action="store", dest="provider-version",
                     default=None, type=str, help="Set the version of the TLS provider")
    parser.addoption(
        "--best-effort-NOT-FOR-CI",
        action="store_true",
        default=False,
        help="""If enabled, run as many tests are possible 
        for the discovered providers, and skip any providers 
        that aren't available""",
    )


def pytest_configure(config: pytest.Config):
    """
    pytest hook that adds the function to deselect tests if the parameters
    don't makes sense.

    This is executed once per pytest session on process startup.
    """
    config.addinivalue_line(
        "markers", "uncollect_if(*, func): function to unselect tests from parametrization"
    )

    if config.getoption("--best-effort-NOT-FOR-CI"):
        config.stash[PATH_CONFIGURATION_KEY] = path_configuration()

    provider_version = config.getoption('provider-version', None)
    if "fips" in provider_version:
        set_flag(S2N_FIPS_MODE, True)
    set_flag(S2N_PROVIDER_VERSION, provider_version)


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
