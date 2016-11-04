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
Simple handshake tests using gnutls-cli
"""

import os
import sys
import ssl
import socket
import subprocess
from s2n_test_constants import *

def try_gnutls_handshake(endpoint, port, priority_str):
    # Fire up s2nd
    s2nd = subprocess.Popen(["../../bin/s2nd", "-c", "test_all", str(endpoint), str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Make sure it's running
    s2nd.stdout.readline()

    # Fire up gnutls-cli, use insecure since s2nd is using a dummy cert
    gnutls_cli = subprocess.Popen(["gnutls-cli", "--priority=" + priority_str,"--insecure", "-p " + str(port), str(endpoint)], 
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    # Write the priority str towards s2nd. Prepend with the 's2n' string to make sure we don't accidently match something
    # in the gnutls-cli handshake output
    written_str = "s2n" + priority_str
    gnutls_cli.stdin.write((written_str + "\n").encode("utf-8"))
    gnutls_cli.stdin.flush()

    # Read it
    found = 0
    for line in range(0, 50):
        output = s2nd.stdout.readline().decode("utf-8")
        if output.strip() == written_str:
            found = 1
            break

    if found == 0:
        return -1

    # Write the cipher name from s2n
    s2nd.stdin.write((written_str + "\n").encode("utf-8"))
    s2nd.stdin.flush()
    found = 0
    for line in range(0, 50):
        output = gnutls_cli.stdout.readline().decode("utf-8")
        if output.strip() == written_str:
            found = 1
            break

    if found == 0:
        return -1

    gnutls_cli.kill()
    gnutls_cli.wait()
    s2nd.kill()
    s2nd.wait()

    return 0


def main(argv):
    if len(argv) < 2:
        print("s2n_handshake_test_gnutls.py host port")
        sys.exit(1)

    print("\nRunning GnuTLS handshake tests with: " + os.popen('gnutls-cli --version | grep -w gnutls-cli').read())
    failed = 0
    for ssl_version in [S2N_SSLv3, S2N_TLS10, S2N_TLS11, S2N_TLS12]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        for cipher in S2N_CIPHERS:
            # Use the Openssl name for printing
            cipher_name = cipher.openssl_name
            cipher_priority_str = cipher.gnutls_priority_str
            cipher_vers = cipher.min_tls_vers

            if ssl_version < cipher_vers:
                continue

            # Add the SSL version to make the cipher priority string fully qualified
            complete_priority_str = cipher_priority_str + ":+" + S2N_PROTO_VERS_TO_GNUTLS[ssl_version]
            ret = try_gnutls_handshake(argv[0], int(argv[1]), complete_priority_str)
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
