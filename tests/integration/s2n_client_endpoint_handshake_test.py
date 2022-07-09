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

import argparse
import os
import subprocess
import sys
import time

from os import environ
from s2n_test_constants import *
from s2n_pq_handshake_test import is_pq_enabled

# If a cipher_preference_version is specified, we will use it while attempting the handshake;
# otherwise, s2n will use the default. If an expected_cipher is specified, the test will pass
# if and only if the handshake is negotiated with that cipher; otherwise, the test will pass
# if the handshake is negotiated with any cipher.
well_known_endpoints = [
    {"endpoint": "www.akamai.com"},
    {"endpoint": "www.amazon.com"},
    {"endpoint": "s3.us-west-2.amazonaws.com"},
    {"endpoint": "www.apple.com"},
    {"endpoint": "www.att.com"},
#    {"endpoint": "www.badssl.com"},
#    {"endpoint": "mozilla-intermediate.badssl.com"},
#    {"endpoint": "mozilla-modern.badssl.com"},
#    {"endpoint": "rsa2048.badssl.com"},
#    {"endpoint": "rsa4096.badssl.com"},
#    {"endpoint": "sha256.badssl.com"},
#    {"endpoint": "sha384.badssl.com"},
#    {"endpoint": "sha512.badssl.com"},
#    {"endpoint": "tls-v1-0.badssl.com"},
#    {"endpoint": "tls-v1-1.badssl.com"},
#    {"endpoint": "tls-v1-2.badssl.com"},
    {"endpoint": "www.cloudflare.com"},
    {"endpoint": "www.ebay.com"},
    {"endpoint": "www.f5.com"},
    {"endpoint": "www.facebook.com"},
    {"endpoint": "www.google.com"},
    {"endpoint": "www.github.com"},
    {"endpoint": "www.ibm.com"},
    {"endpoint": "www.microsoft.com"},
    {"endpoint": "www.mozilla.org"},
    {"endpoint": "www.netflix.com"},
    {"endpoint": "www.openssl.org"},
    {"endpoint": "www.samsung.com"},
    {"endpoint": "www.t-mobile.com"},
    {"endpoint": "www.twitter.com"},
    {"endpoint": "www.verizon.com"},
    {"endpoint": "www.wikipedia.org"},
    {"endpoint": "www.yahoo.com"},
    {"endpoint": "www.youtube.com"},
    {
        "endpoint": "kms.us-east-1.amazonaws.com",
        "cipher_preference_version": "PQ-TLS-1-0-2021-05-24",
        "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "expected_pq_cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
    },
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
    """
    Having our own trust store means we need to update it periodically.
    TODO: warn if there is drift between the OS CA certs and our own.
    see https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/
    """
    s2nc_cmd = ["../../bin/s2nc", "-f", "./trust-store/ca-bundle.crt", "-a", "http/1.1", "-B"] + arguments + [str(endpoint)]
    currentDir = os.path.dirname(os.path.realpath(__file__))
    s2nc = subprocess.Popen(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=currentDir, universal_newlines=True)

    try:
        outs, errs = s2nc.communicate(timeout=5)

        found = 0
        expected_output = "Cipher negotiated: "
        if expected_cipher:
            expected_output += expected_cipher

        for line in range(0, NUM_EXPECTED_LINES_OUTPUT):
            output = str(outs)
            if expected_output in output:
                found = 1
                break

        s2nc.wait()

        if found == 0:
            return -1

        return 0

    except subprocess.TimeoutExpired:
        s2nc.kill()
        return -1

def well_known_endpoints_test(use_corked_io, tls13_enabled, fips_mode):

    arguments = []
    msg = "\n\tTesting s2n Client with Well Known Endpoints"
    opt_list = []

    if tls13_enabled:
        arguments += ["--ciphers", "default_tls13"]
        opt_list += ["TLS 1.3"]
    if use_corked_io:
        arguments += ["-C"]
        opt_list += ["Corked IO"]
    if fips_mode:
        arguments += ["--enter-fips-mode"]
        opt_list += ["FIPS enabled"]

    if len(opt_list) != 0:
        msg += " using "
        if len(opt_list) > 1:
            msg += ", ".join(opt_list[:-2] + [opt_list[-2] + " and " + opt_list[-1]])
        else:
            msg += opt_list[0]

    print(msg + ":")

    maxRetries = 5
    failed = 0
    for endpoint_config in well_known_endpoints:

        endpoint = endpoint_config["endpoint"]
        expected_cipher = endpoint_config.get("expected_cipher")

        if "cipher_preference_version" in endpoint_config:
            arguments += ["-c", endpoint_config["cipher_preference_version"]]

        # Retry handshake in case there are any problems going over the internet
        for i in range(1, maxRetries):
            if i > 1:
                print("Connecting to: %-35sAttempt: %-10s... " % (endpoint, i))

            ret = try_client_handshake(endpoint, arguments, expected_cipher)

            if ret == 0:
                break
            else:
                time.sleep(i)

        print_result("Endpoint: %-35sExpected Cipher: %-40s... " % (endpoint, expected_cipher if expected_cipher else "Any"), ret)
        if ret != 0:
            failed += 1

    return failed


def main(argv):
    parser = argparse.ArgumentParser(description="Run client endpoint handshake tests")
    parser.add_argument("--no-tls13", action="store_true", help="Disable TLS 1.3 tests")
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=S2N_LIBCRYPTO_CHOICES,
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
    args = parser.parse_args()

    if is_pq_enabled(args.libcrypto):
        for endpoint in well_known_endpoints:
            endpoint['expected_cipher'] = endpoint.get('expected_pq_cipher')

    fips_mode = False
    if environ.get("S2N_TEST_IN_FIPS_MODE") is not None:
        fips_mode = True
        print("\nRunning s2nd in FIPS mode.")

    failed = 0

    # TLS 1.2 Tests
    failed += well_known_endpoints_test(use_corked_io=False, tls13_enabled=False, fips_mode=fips_mode)
    failed += well_known_endpoints_test(use_corked_io=True, tls13_enabled=False, fips_mode=fips_mode)

    # TLS 1.3 Tests
    if not args.no_tls13:
        failed += well_known_endpoints_test(use_corked_io=False, tls13_enabled=True, fips_mode=fips_mode)
        failed += well_known_endpoints_test(use_corked_io=True, tls13_enabled=True, fips_mode=fips_mode)

    return failed

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

