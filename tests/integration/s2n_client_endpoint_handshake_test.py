#
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import os
import sys
import time
import socket
import subprocess
import itertools
from s2n_test_constants import *


# If a cipher_preference_version is specified, we will use it while attempting the handshake;
# otherwise, s2n will use the default. If an expected_cipher is specified, the test will pass
# if and only if the handshake is negotiated with that cipher; otherwise, the test will pass
# if the handshake is negotiated with any cipher.
well_known_endpoints = [
    {"endpoint": "amazon.com"},
    {"endpoint": "facebook.com"},
    {"endpoint": "google.com"},
    {"endpoint": "netflix.com"},
    {"endpoint": "s3.amazonaws.com"},
    {"endpoint": "twitter.com"},
    {"endpoint": "wikipedia.org"},
    {"endpoint": "yahoo.com"},
    {"endpoint": "kms.us-east-1.amazonaws.com", "cipher_preference_version": "KMS-PQ-TLS-1-0-2019-06", "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384"},
    {"endpoint": "kms.us-east-1.amazonaws.com", "cipher_preference_version": "PQ-SIKE-TEST-TLS-1-0-2019-11", "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384"}
]

# Make an exception to allow failure (if CI is having issues)
allowed_endpoints_failures = [
    'wikipedia.org'
]

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

def try_client_handshake(endpoint, arguments, expected_cipher):
    s2nc_cmd = ["../../bin/s2nc", "-f", "./trust-store/ca-bundle.crt", "-a", "http/1.1"] + arguments + [str(endpoint)]
    currentDir = os.path.dirname(os.path.realpath(__file__))
    s2nc = subprocess.Popen(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=currentDir)

    found = 0
    expected_output = "Cipher negotiated: "
    if expected_cipher:
        expected_output += expected_cipher

    for line in range(0, 10):
        output = str(s2nc.stdout.readline().decode("utf-8"))
        if expected_output in output:
            found = 1
            break

    s2nc.kill()
    s2nc.wait()

    if found == 0:
        return -1

    return 0

def well_known_endpoints_test(use_corked_io):
    arguments = []
    msg = "\n\tTesting s2n Client with Well Known Endpoints:"
    if use_corked_io:
        msg = "\n\tTesting s2n Client with Well Known Endpoints using Corked IO:"
        arguments += ["-C"]
    print(msg)

    maxRetries = 5
    failed = 0
    for endpoint_config in well_known_endpoints:
        endpoint = endpoint_config["endpoint"]
        expected_cipher = endpoint_config.get("expected_cipher")

        if "cipher_preference_version" in endpoint_config:
            arguments += ["-c", endpoint_config["cipher_preference_version"]]

        # Retry handshake in case there are any problems going over the internet
        for i in range(1, maxRetries):
            ret = try_client_handshake(endpoint, arguments, expected_cipher)
            if ret is 0:
                break
            else:
                time.sleep(i)

        print_result("Endpoint: %-35sExpected Cipher: %-40s... " % (endpoint, expected_cipher if expected_cipher else "Any"), ret)
        if ret != 0 and endpoint not in allowed_endpoints_failures:
            failed += 1

    return failed

def main(argv):
    if len(argv) < 2:
        print("s2n_handshake_test_s_client.py host port")
        sys.exit(1)

    host = argv[0]
    port = argv[1]

    failed = 0
    failed += well_known_endpoints_test(False)
    failed += well_known_endpoints_test(True)
    return failed

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

