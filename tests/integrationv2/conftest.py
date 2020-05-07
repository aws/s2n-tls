import pytest


def pytest_configure(config):
    """
    pytest hook that adds the function to deselect tests if the parameters
    don't makes sense.
    """
    config.addinivalue_line(
        "markers", "uncollect_if(*, func): function to unselect tests from parametrization"
    )


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


def pytest_xdist_node_collection_finished(node, ids):
    """
    NOTE: Unimplemented. This is a placeholder for an xdist hook
    that will help distribute port numbers when tests are run
    in parallel.
    """
    pass


def pytest_configure_node(node):
    """
    NOTE: Unimplemented. This is a placeholder for an xdist hook
    that will help distribute port numbers when tests are run
    in parallel.
    """
    pass
