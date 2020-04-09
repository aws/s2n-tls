#
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
Common functions used to create test openssl servers and clients.
"""

import common.s2n_test_common as util
from common.s2n_test_scenario import Mode, Version
from time import sleep


OPENSSL_SIGNALS = {
    Mode.client: "CONNECTED",
    Mode.server: "ACCEPT",
}


VERSION_ARGS = {
    Version.TLS10: "-tls1",
    Version.TLS11: "-tls1_1",
    Version.TLS12: "-tls1_2",
    Version.TLS13: "-tls1_3",
}


def get_openssl_cmd(scenario):
    openssl_cmd = [ "openssl"]

    if scenario.s2n_mode.is_client():
        openssl_cmd.extend(["s_server", "-accept", str(scenario.port)])
    else:
        openssl_cmd.extend(["s_client", "-connect", str(scenario.host) + ":" + str(scenario.port)])

    openssl_cmd.extend(["-cert", scenario.cert.cert,
                        "-key", scenario.cert.key,
                        "-tlsextdebug"])

    if scenario.version:
        openssl_cmd.append(VERSION_ARGS[scenario.version])

    if scenario.cipher:
        if scenario.version is Version.TLS13:
            openssl_cmd.extend(["-ciphersuites", str(scenario.cipher)])
            openssl_cmd.extend(["-curves", str(scenario.curve)])
        else:
            openssl_cmd.extend(["cipher", str(scenario.cipher)])

    openssl_cmd.extend(scenario.peer_flags)

    return openssl_cmd


def get_openssl(scenario):
    openssl_cmd = get_openssl_cmd(scenario)
    openssl = util.get_process(openssl_cmd)
    
    if not util.wait_for_output(openssl, OPENSSL_SIGNALS[scenario.s2n_mode.other()]):
        raise AssertionError("openssl %s: %s" % (scenario.s2n_mode.other(), util.get_error(openssl)))

    # Openssl outputs the success signal BEFORE binding the socket, so wait a little
    sleep(0.1)

    return openssl


def run_openssl_connection_test(scenarios, **kwargs):
    return util.run_connection_test(get_openssl, scenarios, **kwargs)

