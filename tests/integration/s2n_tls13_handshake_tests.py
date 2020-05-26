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
import uuid

from common.s2n_test_common import wait_for_output
from common.s2n_test_openssl import run_openssl_connection_test
from common.s2n_test_scenario import get_scenarios, Mode, Cipher, Version, Curve
from common.s2n_test_reporting import Result, Status
import common.s2n_test_common as util


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
    marker_found = False
    hello_count = 0
    finished_count = 0
    marker = b"cf 21 ad 74 e5 9a 61 11 be 1d"

    for line in client.stdout:
        if marker in line:
            marker_found = True
        if b'ClientHello' in line:
            hello_count += 1
        if b'], Finished' in line:
            finished_count += 1
        if marker_found and hello_count == 2 and finished_count == 2:
            result.status = Status.PASSED
            break


    return result


def key_update_recv(server, client):
    '''
    This test checks that a key update can be processed by s2n. It runs three times to prove that s2n can
    process several key updates in a row.
    '''
    result = Result()
    result.status = Status.PASSED
    for i in range(3):
        msg = "Message:" + str(uuid.uuid4())
        client.stdin.write(("k\n\n").encode("utf-8"))
        client.stdin.flush()
        line = ''
        # Confirm that the keyupdate was sent
        while('KEYUPDATE' not in line):
            line = client.stderr.readline().decode("utf-8")
        client.stdin.write((msg + "\n\n").encode("utf-8"))
        client.stdin.flush()
        if not (wait_for_output(server, msg, 100)):
            result.status = Status.FAILED
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
    failed += run_openssl_connection_test(get_scenarios(host, port, versions=[Version.TLS13], s2n_modes=[Mode.server], ciphers=Cipher.all(),
                                                        peer_flags=['-msg', '-curves', 'X448:P-256']), test_func=verify_hrr_random_data)
    print("\n\tRunning TLS1.3 key update tests with openssl: %s" % os.popen('openssl version').read())
    failed += run_openssl_connection_test(get_scenarios(host, port, versions=[Version.TLS13], s2n_modes=[Mode.server], ciphers=Cipher.all()),
                                                         test_func=key_update_recv)

    return failed


if __name__ == "__main__":
    sys.exit(main())

