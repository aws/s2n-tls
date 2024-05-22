import pytest
import copy
import os
from enum import Enum, auto

from configuration import available_ports
from common import ProviderOptions, Protocols, random_str
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name, to_bytes

SERVER_STATE_FILE = 'server_state'
CLIENT_STATE_FILE = 'client_state'

SERVER_DATA = f"Some random data from the server:" + random_str(10)
CLIENT_DATA = f"Some random data from the client:" + random_str(10)


class MainlineRole(Enum):
    Serialize = auto()
    Deserialize = auto()


class Mode(Enum):
    Server = auto()
    Client = auto()


"""
This test file checks that a serialized connection can be deserialized by an older version of
s2n-tls and vice versa. This ensures that any future changes we make to the handshake are backwards-compatible
with an older version of s2n-tls.

This feature requires an uninterrupted TCP connection with the peer in-between serialization and
deserialization. Our integration test setup can't easily provide that while also using two different
s2n-tls versions. To get around that we do a hack and serialize/deserialize both peers in the TLS connection.
This prevents one peer from receiving a TCP FIN message and shutting the connection down early.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12], ids=get_parameter_name)
@pytest.mark.parametrize("mainline_role", [MainlineRole.Serialize, MainlineRole.Deserialize], ids=get_parameter_name)
@pytest.mark.parametrize("version_change", [Mode.Server, Mode.Client], ids=get_parameter_name)
def test_server_serialization_backwards_compat(managed_process, tmp_path, protocol, mainline_role, version_change):
    server_state_file = str(tmp_path / SERVER_STATE_FILE)
    client_state_file = str(tmp_path / CLIENT_STATE_FILE)
    assert not os.path.exists(server_state_file)
    assert not os.path.exists(client_state_file)

    options = ProviderOptions(
        port=next(available_ports),
        protocol=protocol,
        insecure=True,
    )

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.extra_flags = ['--serialize-out', client_state_file]

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.extra_flags = ['--serialize-out', server_state_file]

    if mainline_role is MainlineRole.Serialize:
        if version_change == Mode.Server:
            server_options.use_mainline_version = True
        else:
            client_options.use_mainline_version = True

    server = managed_process(
        S2N, server_options, send_marker=S2N.get_send_marker())
    client = managed_process(S2N, client_options, send_marker=S2N.get_send_marker())

    for results in client.get_results():
        results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(protocol.value)) in results.stdout

    for results in server.get_results():
        results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(protocol.value)) in results.stdout

    assert os.path.exists(server_state_file)
    assert os.path.exists(client_state_file)

    client_options.extra_flags = ['--deserialize-in', client_state_file]
    server_options.extra_flags = ['--deserialize-in', server_state_file]
    if mainline_role is MainlineRole.Deserialize:
        if version_change == Mode.Server:
            server_options.use_mainline_version = True
        else:
            client_options.use_mainline_version = True

    server_options.data_to_send = SERVER_DATA.encode()
    client_options.data_to_send = CLIENT_DATA.encode()

    server = managed_process(S2N, server_options, send_marker=CLIENT_DATA)
    client = managed_process(S2N, client_options, send_marker="Connected to localhost", close_marker=SERVER_DATA)

    for results in server.get_results():
        results.assert_success()
        # No protocol version printout since deserialization means skipping the handshake
        assert to_bytes("Actual protocol version:") not in results.stdout
        assert CLIENT_DATA.encode() in results.stdout

    for results in client.get_results():
        results.assert_success()
        assert to_bytes("Actual protocol version:") not in results.stdout
        assert SERVER_DATA.encode() in results.stdout
