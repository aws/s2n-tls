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
Handshake tests using Openssl s_client against s2nd
Openssl 1.1.0 removed SSLv3, 3DES, an RC4, so we won't have coverage there.
"""

import os
import sys
import time
import socket
import subprocess
import itertools
from s2n_test_constants import *

PROTO_VERS_TO_S_CLIENT_ARG = {
    S2N_TLS10 : "-tls1",
    S2N_TLS11 : "-tls1_1",
    S2N_TLS12 : "-tls1_2",
}

def cleanup_processes(*processes):
    for p in processes:
        p.kill()
        p.wait()
        
def try_handshake(endpoint, port, cipher, ssl_version, sig_algs=None, curves=None, resume=False,
        prefer_low_latency=False, clientAuth=None):
    """
    Attempt to handshake against s2nd listening on `endpoint` and `port` using Openssl s_client

    :param int endpoint: endpoint for s2nd to listen on
    :param int port: port for s2nd to listen on
    :param str cipher: ciphers for Openssl s_client to offer. See https://www.openssl.org/docs/man1.0.2/apps/ciphers.html
    :param int ssl_version: SSL version for s_client to use
    :param str sig_algs: Signature algorithms for s_client to offer
    :param str curves: Elliptic curves for s_client to offer
    :param bool resume: True if s_client should try to reconnect to s2nd and reuse the same TLS session. False for normal negotiation.
    :param bool prefer_low_latency: True if s2nd should use 1500 for max outgoing record size. False for default max.
    :return: 0 on successfully negotiation(s), -1 on failure
    """
    # Fire up s2nd
    s2nd_cmd = ["../../bin/s2nd", "-c", "test_all"]
    if prefer_low_latency == True:
        s2nd_cmd.append("--prefer-low-latency")
    if clientAuth is not None:
        s2nd_cmd.append("-m")
    s2nd_cmd.extend([str(endpoint), str(port)])
    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Make sure it's running
    s2nd.stdout.readline()

    s_client_cmd = ["../../libcrypto-root/bin/openssl", "s_client", PROTO_VERS_TO_S_CLIENT_ARG[ssl_version], "-quiet",
            "-connect", str(endpoint) + ":" + str(port)]
    if cipher is not None:
        s_client_cmd.extend(["-cipher", cipher])
    if sig_algs is not None:
        s_client_cmd.extend(["-sigalgs", sig_algs])
    if curves is not None:
        s_client_cmd.extend(["-curves", curves])
    if resume == True:
        s_client_cmd.append("-reconnect")
    if clientAuth is not None:
        s_client_cmd.extend(["-key", "./test_certs/client_2048_rsa.key"])
        s_client_cmd.extend(["-cert", "./test_certs/client_2048_rsa.cert"])

    # Fire up s_client
    s_client = subprocess.Popen(s_client_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    # Validate that s_client resumes successfully against s2nd
    if resume is True:
        seperators = 0
        for line in s2nd.stdout:
            line = line.decode("utf-8").strip()
            if line.startswith("Resumed session"):
                seperators += 1
            if seperators == 5:
                break

        if seperators != 5:
            cleanup_processes(s2nd, s_client)
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
        cleanup_processes(s2nd, s_client)
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
        cleanup_processes(s2nd, s_client)
        return -1

    cleanup_processes(s2nd, s_client)

    return 0

def print_result(result_prefix, return_code):
    print(result_prefix, end='')
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

def handshake_test(host, port):
    """
    Basic handshake tests using all valid combinations of supported cipher suites and TLS versions.
    """
    print("\n\tRunning handshake tests:")
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

            ret = try_handshake(host, port, cipher_name, ssl_version)
            result_prefix = "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
            print_result(result_prefix, ret)
            if ret != 0:
                failed = 1

    return failed

def resume_test(host, port):
    """
    Tests s2n's session resumption capability using all valid combinations of cipher suite and TLS version.
    """
    print("\n\tRunning resumption tests:")
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

            ret = try_handshake(host, port, cipher_name, ssl_version, resume=True)
            result_prefix = "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
            print_result(result_prefix, ret)
            if ret != 0:
                failed = 1

    return failed

def sigalg_test(host, port, useClientAuth=None):
    """
    Acceptance test for supported signature algorithms. Tests all possible supported sigalgs with unsupported ones mixed in
    for noise.
    """
    supported_sigs = ["RSA+SHA1", "RSA+SHA224", "RSA+SHA256", "RSA+SHA384", "RSA+SHA512"]
    unsupported_sigs = ["ECDSA+SHA256", "DSA+SHA384", "ECDSA+SHA512", "DSA+SHA1"]
    print("\n\tRunning signature algorithm tests:")
    print("\tExpected supported:   " + str(supported_sigs))
    print("\tExpected unsupported: " + str(unsupported_sigs))

    failed = 0
    for size in range(1, len(supported_sigs) + 1):
        print("\n\t\tTesting ciphers using signature preferences of size: " + str(size))

        # Produce permutations of every accepted signature alrgorithm in every possible order
        for permutation in itertools.permutations(supported_sigs, size):
            # Put some unsupported algs in front to make sure we gracefully skip them
            mixed_sigs = unsupported_sigs + list(permutation)
            mixed_sigs_str = ':'.join(mixed_sigs)
            # Try an ECDHE cipher suite and a DHE one
            for cipher in filter(lambda x: x.openssl_name == "ECDHE-RSA-AES128-GCM-SHA256" or x.openssl_name == "DHE-RSA-AES128-GCM-SHA256", S2N_CIPHERS):
                ret = try_handshake(host, port, cipher.openssl_name, S2N_TLS12, sig_algs=mixed_sigs_str, clientAuth=useClientAuth)
                # Trim the RSA part off for brevity. User should know we are only supported RSA at the moment.
                prefix = "Digests: %-45s ClientAuth: %-5s Vers: %-8s... " % (':'.join([x[4:] for x in permutation]), str(useClientAuth), S2N_PROTO_VERS_TO_STR[S2N_TLS12])
                print_result(prefix, ret)
                if ret != 0:
                    failed = 1
    return failed

def elliptic_curve_test(host, port):
    """
    Acceptance test for supported elliptic curves. Tests all possible supported curves with unsupported curves mixed in
    for noise.
    """
    supported_curves = ["P-256", "P-384"]
    unsupported_curves = ["B-163", "K-409"]
    print("\n\tRunning elliptic curve tests:")
    print("\tExpected supported:   " + str(supported_curves))
    print("\tExpected unsupported: " + str(unsupported_curves))

    failed = 0
    for size in range(1, len(supported_curves) + 1):
        print("\n\t\tTesting ciphers using curve list of size: " + str(size))

        # Produce permutations of every accepted curve in every possible order
        for permutation in itertools.permutations(supported_curves, size):
            # Put some unsupported curves in front to make sure we gracefully skip them
            mixed_curves = unsupported_curves + list(permutation)
            mixed_curves_str = ':'.join(mixed_curves)
            for cipher in filter(lambda x: x.openssl_name == "ECDHE-RSA-AES128-GCM-SHA256" or x.openssl_name == "ECDHE-RSA-AES128-SHA", S2N_CIPHERS):
                ret = try_handshake(host, port, cipher.openssl_name, S2N_TLS12, curves=mixed_curves_str)
                prefix = "Curves: %-40s Vers: %10s ... " % (':'.join(list(permutation)), S2N_PROTO_VERS_TO_STR[S2N_TLS12])
                print_result(prefix, ret)
                if ret != 0:
                    failed = 1
    return failed

def elliptic_curve_fallback_test(host, port):
    """
    Tests graceful fallback when s2n doesn't support any curves offered by the client. A non-ecc suite should be
    negotiated.
    """
    failed = 0
    # Make sure s2n can still negotiate a non-EC kx(AES256-GCM-SHA384) suite if we don't match anything on the client
    unsupported_curves = ["B-163", "K-409"]
    ret = try_handshake(host, port, "ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384", S2N_TLS12, curves=":".join(unsupported_curves))
    print_result("%-65s ... " % "Testing curve mismatch fallback", ret)
    if ret != 0:
        failed = 1

    return failed


def handshake_fragmentation_test(host,port):
    """
    Tests negotation with s_client despite message fragmentation. Max record size is clamped to force s2n
    to fragment the ServerCertifcate message.
    """
    print("\n\tRunning handshake fragmentation tests:")
    failed = 0
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        # Cipher isn't relevant for this test, pick one available in all TLS versions
        cipher_name = "ECDHE-RSA-AES128-SHA"

        # Low latency option indirectly forces fragmentation.
        ret = try_handshake(host, port, cipher_name, ssl_version, prefer_low_latency=True)
        result_prefix = "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
        print_result(result_prefix, ret)
        if ret != 0:
            failed = 1
    return failed

def client_auth_test(host, port):
    print("\n\tRunning Client Auth Handshake Tests:")
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

            ret = try_handshake(host, port, cipher_name, ssl_version, clientAuth = True)
            result_prefix = "Cipher: %-28s Vers: %-8s ClientAuth: True... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
            print_result(result_prefix, ret)
            if ret != 0:
                failed = 1
    return failed

def main(argv):
    if len(argv) < 2:
        print("s2n_handshake_test_s_client.py host port")
        sys.exit(1)

    print("\nRunning tests with: " + os.popen('../../libcrypto-root/bin/openssl version').read())

    host = argv[0]
    port = argv[1]
    failed = 0
    failed += client_auth_test(host, port)
    failed += resume_test(host, port)
    failed += handshake_test(host, port)
    failed += sigalg_test(host, port)
    failed += sigalg_test(host, port, useClientAuth=True)
    failed += elliptic_curve_test(host, port)
    failed += elliptic_curve_fallback_test(host, port)
    failed += handshake_fragmentation_test(host,port)
    return failed

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

