##
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

"""
Common functions to run s2n integration tests.
"""

import subprocess
import uuid

from common.s2n_test_scenario import Mode, Version, run_scenarios, get_libcrypto
from common.s2n_test_reporting import Result


def get_error(process, line_limit=10):
    error = ""
    for count in range(line_limit):
        line = process.stderr.readline().decode("utf-8")
        if line:
            error += line + "\t"
        else:
            return error
    return error


def wait_for_output(process, marker, line_limit=10):
    for count in range(line_limit):
        line = process.stdout.readline().decode("utf-8")
        if marker in line:
            return True
    return False


def cleanup_processes(*processes):
    for p in filter(None, processes):
        p.kill()
        p.wait()


def get_process(cmd):
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def basic_write_test(server, client):
    server_msg = "Message:" + str(uuid.uuid4())
    server.stdin.write((server_msg + "\n\n").encode("utf-8"))
    server.stdin.flush()

    if not wait_for_output(client, server_msg, line_limit=100):
        return Result("Failed to write '%s' from server to client" % (server_msg))

    client_msg = "Message:" + str(uuid.uuid4())
    client.stdin.write((client_msg + "\n\n").encode("utf-8"))
    client.stdin.flush()

    if not wait_for_output(server, client_msg, line_limit=100):
        return Result("Failed to write %s from client to server" % (client_msg))

    return Result()


def connect(get_peer, scenario):
    """
    Perform a handshake between s2n and another TLS process.

    Args:
        get_peer: a function that returns a TLS process
        scenario: the handshake configuration

    Returns:
        A tuple of (client, server) processes which have completed a handshake.

    """
    server = get_s2n(scenario) if scenario.s2n_mode.is_server() else get_peer(scenario)
    client = get_peer(scenario) if scenario.s2n_mode.is_server() else get_s2n(scenario)

    return (server, client)


def run_connection_test(get_peer, scenarios, test_func=basic_write_test):
    """
    For each scenarios, s2n will attempt to perform a handshake with another TLS process
    and then run the given test.

    Args:
        get_peer: a function that returns a TLS process for s2n to communicate with.
            For an example of how to use this argument, see s2n_test_openssl.py.
        scenarios: a list of handshake configurations
        test_func: a function that takes a server and client process, performs some
            additional testing, and then returns a Result

    Returns:
        A Result object indicating success or failure. If the given test returns
        false or either the connection or the test throw an AssertionError, the Result
        will indicate failure.

    """
    def __test(scenario):
        client = None
        server = None
        result = Result("Unknown Error")
        try:
            server, client = connect(get_peer, scenario)
            result = test_func(server, client) if test_func else Result()

            if result.is_success() and client.poll() is not None:
                result = Result("Client process crashed")
            if result.is_success() and server.poll() is not None:
                result = Result("Server process crashed")

        except AssertionError as error:
            result = Result(error)
        finally:
            cleanup_processes(server, client)
            if client:
                result.client_error = get_error(client)
            if server:
                result.server_error = get_error(server)
            return result

    return run_scenarios(__test, scenarios)


def get_s2n_cmd(scenario):
    mode_char = 'c' if scenario.s2n_mode.is_client() else 'd'

    s2n_cmd = [ "../../bin/s2n%c" % mode_char,
                "-c", "test_all",
                "--insecure"]

    if scenario.s2n_mode.is_server():
        s2n_cmd.extend(["--key", scenario.cert.key])
        s2n_cmd.extend(["--cert", scenario.cert.cert])
    else:
        s2n_cmd.append("--echo")

    if scenario.version is Version.TLS13:
        s2n_cmd.append("--tls13")
        if get_libcrypto() == "openssl-1.1.1":
            s2n_cmd.extend(["--curves", "default_tls13"])

    s2n_cmd.extend(scenario.s2n_flags)
    s2n_cmd.extend([str(scenario.host), str(scenario.port)])

    return s2n_cmd


S2N_SIGNALS = {
    Mode.client: "Connected to",
    Mode.server: "Listening on"
}

def get_s2n(scenario):
    s2n_cmd = get_s2n_cmd(scenario)
    s2n = get_process(s2n_cmd)

    if not wait_for_output(s2n, S2N_SIGNALS[scenario.s2n_mode]):
        raise AssertionError("s2n %s: %s" % (scenario.s2n_mode, get_error(s2n)))

    return s2n

