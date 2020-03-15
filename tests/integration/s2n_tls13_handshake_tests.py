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


def main():
    parser = argparse.ArgumentParser(description='Runs TLS1.3 minimal handshake integration tests against Openssl')
    parser.add_argument('host', help='The host to connect to')
    parser.add_argument('port', type=int, help='The port to bind to')

    args = parser.parse_args()
    host = args.host
    port = args.port

    failed = 0

    print("\n\tRunning TLS1.3 handshake tests with openssl: %s" % os.popen('openssl version').read())
    failed += run_openssl_connection_test(get_scenarios(host, port, versions=[Version.TLS13], s2n_modes=Mode.all(), ciphers=Cipher.all(), curves=Curve.all()))

    return failed


if __name__ == "__main__":
    sys.exit(main())

