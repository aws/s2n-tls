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

from s2n_test_constants import NUM_EXPECTED_LINES_OUTPUT, ACTUAL_VERSION_STR, S2N_TLS12

"""
PQ Handshake tests: s2nd and s2nc negotiate a handshake using Kyber PQ KEM
"""

import argparse
import os
from os import environ
import sys
import subprocess
from s2n_test_constants import S2N_LIBCRYPTO_CHOICES

pq_handshake_test_vectors = [
    # The first set of vectors specify client and server cipher preference versions that are compatible for a successful PQ handshake
    {"client_ciphers": "KMS-PQ-TLS-1-0-2019-06", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2019-06", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2019-06", "server_ciphers": "KMS-PQ-TLS-1-0-2020-07", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},

    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2020-07", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},

    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-07", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-07", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-07", "server_ciphers": "KMS-PQ-TLS-1-0-2020-07", "expected_cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384", "expected_kem": "kyber512r3"},

    {"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2019-11", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2019-11", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2019-11", "server_ciphers": "KMS-PQ-TLS-1-0-2020-07", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},

    {"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "PQ-SIKE-TEST-TLS-1-0-2020-02", "server_ciphers": "KMS-PQ-TLS-1-0-2020-07", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},

    # The last set of vectors specify a "mismatch" between PQ cipher preferences - a classic handshake should be completed
    {"client_ciphers": "KMS-PQ-TLS-1-0-2019-06", "server_ciphers": "KMS-TLS-1-0-2018-10", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-02", "server_ciphers": "KMS-TLS-1-0-2018-10", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-PQ-TLS-1-0-2020-07", "server_ciphers": "KMS-TLS-1-0-2018-10", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},

    {"client_ciphers": "KMS-TLS-1-0-2018-10", "server_ciphers": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-TLS-1-0-2018-10", "server_ciphers": "KMS-PQ-TLS-1-0-2020-02", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": "KMS-TLS-1-0-2018-10", "server_ciphers": "KMS-PQ-TLS-1-0-2020-07", "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
]


def is_pq_enabled(libcrypto):
    if os.getenv("S2N_NO_PQ"): return False
    if libcrypto == "openssl-1.0.2-fips": return False
    return True


def validate_version(expected_version, line):
    return ACTUAL_VERSION_STR.format(expected_version or S2N_TLS12) in line

def print_result(result_prefix, return_code):
    print(result_prefix, end="")
    if return_code == 0:
        if sys.stdout.isatty():
            print("\033[32;1mPASSED\033[0m")
        else:
            print("PASSED")
    else:
        if sys.stdout.isatty():
            print("\033[31;1mFAILED\033[0m")
        else:
            print("FAILED")

def do_pq_handshake(client_ciphers, server_ciphers, expected_cipher, expected_kem, host, port):
    s2nd_cmd = ["../../bin/s2nd", "--negotiate", "--ciphers", server_ciphers, host, port]
    s2nc_cmd = ["../../bin/s2nc", "-i", "--ciphers", client_ciphers, host, port]
    current_dir = os.path.dirname(os.path.realpath(__file__))

    expected_cipher_output = "Cipher negotiated: " + expected_cipher
    expected_kem_output = "KEM: " + expected_kem

    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=current_dir, universal_newlines=True)
    s2nc = subprocess.Popen(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=current_dir, universal_newlines=True)

    client_kem_found = False
    client_cipher_found = False
    client_version_correct = False
    server_kem_found = False
    server_cipher_found = False
    server_version_correct = False

    for i in range(0, NUM_EXPECTED_LINES_OUTPUT):
        client_outs, errs = s2nc.communicate(timeout=5)
        client_line = str(client_outs)

        if expected_kem_output in client_line:
            client_kem_found = True
        if expected_cipher_output in client_line:
            client_cipher_found = True
        if validate_version(S2N_TLS12, client_line):
            client_version_correct = True

        server_outs, errs = s2nc.communicate(timeout=5)
        server_line = str(server_outs)
        if expected_kem_output in server_line:
            server_kem_found = True
        if expected_cipher_output in server_line:
            server_cipher_found = True
        if validate_version(S2N_TLS12, server_line):
            server_version_correct = True

    s2nc.wait()

    s2nd.kill()
    s2nd.wait()

    if not (client_kem_found and server_kem_found and client_cipher_found and server_cipher_found):
        return 1

    if not (client_version_correct and server_version_correct):
        return 1

    return 0

def main():
    parser = argparse.ArgumentParser(description='Runs PQ handshake integration tests using s2nd and s2nc.')
    parser.add_argument('host', help='The host for s2nd to bind to')
    parser.add_argument('port', type=int, help='The port for s2nd to bind to')
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=S2N_LIBCRYPTO_CHOICES,
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
    args = parser.parse_args()
    host = str(args.host)
    port = str(args.port)

    if not is_pq_enabled(args.libcrypto):
        print("\nSkipping s2n_pq_handshake_test because PQ KEMs are not supported...\n")
        return 0
    else:
        print("\nRunning s2n_pq_handshake_test using s2nd and s2nc with host: %s and port: %s...\n" % (host, port))

    failed = 0

    for test_vector in pq_handshake_test_vectors:
        client_ciphers = test_vector["client_ciphers"]
        server_ciphers = test_vector["server_ciphers"]
        expected_cipher = test_vector["expected_cipher"]
        expected_kem = test_vector["expected_kem"]

        test_result = do_pq_handshake(client_ciphers, server_ciphers, expected_cipher, expected_kem, host, port)
        failed += test_result
        print_result("Client Ciphers: %-30sServer Ciphers: %-28sExpected Cipher: %-37sExpected KEM: %-20s"
                     % (client_ciphers, server_ciphers, expected_cipher, expected_kem), test_result)

    return failed

if __name__ == "__main__":
    sys.exit(main())
