import pytest
import copy
import os

from configuration import available_ports
from common import ProviderOptions, Protocols
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name

SERVER_STATE_FILE = 'server_state'
CLIENT_STATE_FILE = 'client_state'

"""
This test file checks that a serialized connection can be deserialized by an older version of
s2n-tls and vice versa. This ensures that any future changes we make to the handshake are backwards-compatible
with an older version of s2n-tls.

This feature requires an uninterrupted TCP connection with the peer in-between serialization and
deserialization. Our integration test setup can't provide that while also using two different s2n-tls
versions. To get around that we do a hack and serialize/deserialize both peers in the TLS connection.
This prevents one peer from receiving a TCP FIN message and shutting the connection down early.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12], ids=get_parameter_name)
def test_serialize_new_deserialize_old(managed_process, tmp_path, protocol, provider, other_provider):
    server_state_file = str(tmp_path / SERVER_STATE_FILE)
    client_state_file = str(tmp_path / CLIENT_STATE_FILE)
    assert not os.path.exists(server_state_file)
    assert not os.path.exists(client_state_file)

    options = ProviderOptions(
        port=next(available_ports),
        insecure=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = ['--serialize-out', client_state_file]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.extra_flags = ['--serialize-out', server_state_file]

    server = managed_process(
        S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(S2N, client_options, send_marker=S2N.get_send_marker())

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()

    assert os.path.exists(server_state_file)
    assert os.path.exists(client_state_file)

    client_options.extra_flags = ['--deserialize-in', client_state_file]
    server_options.extra_flags = ['--deserialize-in', server_state_file]
    server_options.use_mainline_version=True

    server = managed_process(S2N, server_options, send_marker="Listening on localhost")
    client = managed_process(S2N, client_options, send_marker="Connected to localhost")

    for results in server.get_results():
        results.assert_success()

    for results in client.get_results():
        results.assert_success()

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12], ids=get_parameter_name)
def test_serialize_old_deserialize_new(managed_process, tmp_path, protocol, provider, other_provider):
    server_state_file = str(tmp_path / SERVER_STATE_FILE)
    client_state_file = str(tmp_path / CLIENT_STATE_FILE)
    assert not os.path.exists(server_state_file)
    assert not os.path.exists(client_state_file)

    options = ProviderOptions(
        port=next(available_ports),
        insecure=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = ['--serialize-out', client_state_file]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.extra_flags = ['--serialize-out', server_state_file]
    server_options.use_mainline_version=True

    server = managed_process(
        S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(S2N, client_options, send_marker=S2N.get_send_marker())

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()

    assert os.path.exists(server_state_file)
    assert os.path.exists(client_state_file)

    client_options.extra_flags = ['--deserialize-in', client_state_file]
    server_options.extra_flags = ['--deserialize-in', server_state_file]
    server_options.use_mainline_version=False

    server = managed_process(S2N, server_options, send_marker="Listening on localhost")
    client = managed_process(S2N, client_options, send_marker="Connected to localhost")

    for results in client.get_results():
        results.assert_success()

    for results in server.get_results():
        results.assert_success()
