from global_flags import set_flag, S2N_PROVIDER_VERSION, S2N_FIPS_MODE, S2N_NO_PQ, S2N_USE_CRITERION


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
    config.addinivalue_line(
        "markers", "uncollect_if(*, func): function to unselect tests from parametrization"
    )

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
