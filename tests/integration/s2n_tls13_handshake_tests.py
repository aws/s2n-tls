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
Handshake tests against openssl using TLS13.
At the moment these tests are expected fail, as TLS13 is incomplete.
"""

import argparse
import os
import sys

from common.s2n_test_openssl import run_openssl_connection_test
from common.s2n_test_scenario import get_scenarios, Mode, Cipher, Version, Curve
from common.s2n_test_reporting import Result, Status
import common.s2n_test_common as util


# An unsupported curve followed by a supported curve will cause OpenSSL
# to advertise the supported curve, but only generate a keyshare for
# the unsupported curve. This will make S2N send a HelloRetryRequest.
HRR_ORDERED_CURVES = [
    Curve('X448', Version.TLS13),
    Curve('P-256', Version.TLS13)
]


def verify_hrr_random_data(server, client):
    """
    This callback verifies a HelloRetryRequest was sent from the S2N
    server. If the rest of the integration test passes as well, then
    the handshake completed after the HelloRetryRequest was sent.
    """
    result = Result()
    result.status = Status.FAILED

    # Start of HRR random data which will be printed in the
    # client process output
    marker = b"cf 21 ad 74 e5 9a 61 11 be 1d"
    for line in client.stdout:
        print("Checking line: {}".format(line))
        if marker in line:
            result.status = Status.PASSED
            break

    return result


def main():
    parser = argparse.ArgumentParser(description='Runs TLS1.3 minimal handshake integration tests against Openssl')
    parser.add_argument('host', help='The host to connect to')
    parser.add_argument('port', type=int, help='The port to bind to')

    args = parser.parse_args()
    host = args.host
    port = args.port

    failed = 0

    print("\n\tRunning TLS1.3 handshake tests with openssl: %s" % os.popen('openssl version').read())
    failed += run_openssl_connection_test(get_scenarios(host, port, versions=[Version.TLS13], s2n_modes=Mode.all(), ciphers=Cipher.all()))
    print("\n\tRunning TLS1.3 HRR tests with openssl: %s" % os.popen('openssl version').read())
    failed += run_openssl_connection_test(get_scenarios(host, port, versions=[Version.TLS13], s2n_modes=[Mode.server], ciphers=Cipher.all(), peer_flags=['-tlsextdebug', '-msg', '-curves', 'X448:P-256']), test_func=verify_hrr_random_data)

    return failed


if __name__ == "__main__":
    sys.exit(main())

