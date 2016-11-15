#
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
Session resumption tests using Openssl s_client against s2nd with session caching.
Openssl 1.1.0 removed SSLv3, 3DES, an RC4, so we won't have coverage there.
"""

import os
import sys
import time
import socket
import subprocess
from s2n_test_constants import *

PROTO_VERS_TO_S_CLIENT_ARG = {
    S2N_TLS10 : "-tls1",
    S2N_TLS11 : "-tls1_1",
    S2N_TLS12 : "-tls1_2",
}

def try_resume(endpoint, port, cipher, ssl_version):
    # Fire up s2nd
    s2nd = subprocess.Popen(["../../bin/s2nd", "-c", "test_all", str(endpoint), str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Make sure it's running
    s2nd.stdout.readline()

    # Fire up s_client
    s_client = subprocess.Popen(["../../libcrypto-root/bin/openssl", "s_client", PROTO_VERS_TO_S_CLIENT_ARG[ssl_version], "-cipher", cipher,
                                 "-quiet", "-reconnect", "-connect", str(endpoint) + ":" + str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)

    # Wait until the 6th connection
    seperators = 0
    for line in s2nd.stdout:
        line = line.decode("utf-8").strip()
        if line.startswith("Resumed session"):
            seperators += 1
        if seperators == 5:
            break

    if seperators != 5:
        return -1

    # Write the cipher name towards s2n
    s_client.stdin.write((cipher + "\n").encode("utf-8"))
    s_client.stdin.flush()

    # Read it
    found = 0
    for line in range(0, 10):
        output = s2nd.stdout.readline().decode("utf-8")
        if output.strip() == cipher:
            found = 1
            break

    if found == 0:
        return -1

    # Write the cipher name from s2n
    s2nd.stdin.write((cipher + "\n").encode("utf-8"))
    s2nd.stdin.flush()
    found = 0
    for line in range(0, 10):
        output = s_client.stdout.readline().decode("utf-8")
        if output.strip() == cipher:
            found = 1
            break

    if found == 0:
        return -1

    s_client.kill()
    s_client.wait()
    s2nd.kill()
    s2nd.wait()

    return 0

def main(argv):
    if len(argv) < 2:
        print("s2n_resume_test.py host port")
        sys.exit(1)

    print("\nRunning resumption tests with: " + os.popen('../../libcrypto-root/bin/openssl version').read())
    failed = 0
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        for cipher in S2N_CIPHERS:
            cipher_name = cipher.openssl_name
            cipher_vers = cipher.min_tls_vers

            # Skip the cipher if openssl can't test it. 3DES/RC4 are disabled by default in 1.1.0
            if not cipher.openssl_1_1_0_compatible:
                continue

            if ssl_version < cipher_vers:
                continue

            ret = try_resume(argv[0], int(argv[1]), cipher_name, ssl_version)
            print("Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version]), end='')
            if ret == 0:
                if sys.stdout.isatty():
                    print("\033[32;1mPASSED\033[0m")
                else:
                    print("PASSED")
            else:
                if sys.stdout.isatty():
                    print("\033[31;1mFAILED\033[0m")
                else:
                    print("FAILED")
                failed = 1
    return failed

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
