#
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
Handshake tests using s2nc against Openssl s_server
Openssl 1.1.0 removed SSLv3, 3DES, an RC4, so we won't have coverage there.
"""

import argparse
import os
import sys
import subprocess
import itertools
import multiprocessing
from multiprocessing.pool import ThreadPool
from s2n_test_constants import *
from time import sleep

PROTO_VERS_TO_S_SERVER_ARG = {
    S2N_TLS10: "-tls1",
    S2N_TLS11: "-tls1_1",
    S2N_TLS12: "-tls1_2",
}

use_corked_io=False


def get_supported_curves_list_by_version(libcrypto_version):
   # Curve X25519 is supported for Openssl 1.1.0 and higher
    if libcrypto_version == "openssl-1.1.1":
        return ["P-256", "P-384", "X25519"]
    else:
        return ["P-256", "P-384"]

def cleanup_processes(*processes):
    for p in processes:
        p.kill()
        p.wait()

def try_handshake(endpoint, port, cipher, ssl_version, server_cert=None, server_key=None, sig_algs=None, curves=None, dh_params=None, resume=False, no_ticket=False):
    """
    Attempt to handshake against Openssl s_server listening on `endpoint` and `port` using s2nc

    :param int endpoint: endpoint for Openssl s_server to listen on
    :param int port: port for Openssl s_server to listen on
    :param str cipher: ciphers for Openssl s_server to use. See https://www.openssl.org/docs/man1.0.2/apps/ciphers.html
    :param int ssl_version: SSL version for Openssl s_server to use
    :param str server_cert: path to certificate for Openssl s_server to use
    :param str server_key: path to private key for Openssl s_server to use
    :param str sig_algs: Signature algorithms for Openssl s_server to accept
    :param str curves: Elliptic curves for Openssl s_server to accept
    :param str dh_params: path to DH params for Openssl s_server to use
    :param bool resume: if s2n client has to use reconnect option
    :param bool no_ticket: if s2n client has to not use session ticket
    :return: 0 on successfully negotiation(s), -1 on failure
    """

    # Override certificate for ECDSA if unspecified. We can remove this when we
    # support multiple certificates
    if server_cert is None and cipher is not None and "ECDSA" in cipher:
        server_cert = TEST_ECDSA_CERT
        server_key = TEST_ECDSA_KEY

    if server_cert is None:
        server_cert = TEST_RSA_CERT
        server_key = TEST_RSA_KEY

    if dh_params is None:
        dh_params = TEST_DH_PARAMS

    # Start Openssl s_server
    s_server_cmd = ["openssl", "s_server", "-accept", str(port)]

    if ssl_version is not None:
        s_server_cmd.append(PROTO_VERS_TO_S_SERVER_ARG[ssl_version])
    if server_cert is not None:
        s_server_cmd.extend(["-cert", server_cert])
    if server_key is not None:
        s_server_cmd.extend(["-key", server_key])
    if cipher is not None:
        s_server_cmd.extend(["-cipher", cipher])
    if sig_algs is not None:
        s_server_cmd.extend(["-sigalgs", sig_algs])
    if curves is not None:
        s_server_cmd.extend(["-curves", curves])
    if dh_params is not None:
        s_server_cmd.extend(["-dhparam", dh_params])

    # Fire up s_server
    s_server = subprocess.Popen(s_server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Make sure it's accepting
    found = 0
    for line in range(0, 10):
        output = s_server.stdout.readline().decode("utf-8")
        if output.strip() == "ACCEPT":
            # Openssl first prints ACCEPT and only then actually binds the socket, so wait for a bit...
            sleep(0.1)
            found = 1
            break

    if not found:
        sys.stderr.write("Failed to start s_server: {}\nSTDERR: {}\n".format(" ".join(s_server_cmd), s_server.stderr.read().decode("utf-8")))
        cleanup_processes(s_server)
        return -1

    # Fire up s2nc
    s2nc_cmd = ["../../bin/s2nc", "-c", "test_all", "-i"]
    if resume:
        s2nc_cmd.append("-r")
    if no_ticket:
        s2nc_cmd.append("-T")
    if use_corked_io:
        s2nc_cmd.append("-C")
    s2nc_cmd.extend([str(endpoint), str(port)])

    s2nc = subprocess.Popen(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Read from s2nc until we get successful connection message
    found = 0
    seperators = 0
    if resume:
        for line in s2nc.stdout:
            line = line.decode("utf-8").strip()
            if line.startswith("Resumed session"):
                seperators += 1

            if seperators == 5:
                found = 1
                break
    else:
        for line in range(0, 10):
            output = s2nc.stdout.readline().decode("utf-8")
            if output.strip() == "Connected to {}:{}".format(endpoint, port):
                found = 1
                break

    cleanup_processes(s2nc, s_server)

    if not found:
        sys.stderr.write("= TEST FAILED =\ns_server cmd: {}\n s_server STDERR: {}\n\ns2nc cmd: {}\nSTDERR {}\n".format(" ".join(s_server_cmd), s_server.stderr.read().decode("utf-8"), " ".join(s2nc_cmd), s2nc.stderr.read().decode("utf-8")))
        return -1

    return 0


def cert_path_to_str(cert_path):
    # Converts a path to a cert into a string usable for printing to test output
    # Example: "./test_certs/rsa_2048_sha256_client_cert.pem" => "RSA-2048-SHA256"
    return '-'.join(cert_path[cert_path.rfind('/')+1:].split('_')[:3]).upper()


def print_result(result_prefix, return_code):
    suffix = ""
    if return_code == 0:
        if sys.stdout.isatty():
            suffix = "\033[32;1mPASSED\033[0m"
        else:
            suffix = "PASSED"
    else:
        if sys.stdout.isatty():
            suffix = "\033[31;1mFAILED\033[0m"
        else:
            suffix ="FAILED"

    print(result_prefix + suffix)


def create_thread_pool():
    threadpool_size = multiprocessing.cpu_count() * 2  #Multiply by 2 since performance improves slightly if CPU has hyperthreading
    print("\tCreating ThreadPool of size: " + str(threadpool_size))
    threadpool = ThreadPool(processes=threadpool_size)
    return threadpool


def run_handshake_test(host, port, ssl_version, cipher):
    cipher_name = cipher.openssl_name
    cipher_vers = cipher.min_tls_vers

    # Skip the cipher if openssl can't test it. 3DES/RC4 are disabled by default in 1.1.1
    if not cipher.openssl_1_1_1_compatible:
        return 0

    if ssl_version and ssl_version < cipher_vers:
        return 0

    ret = try_handshake(host, port, cipher_name, ssl_version)

    result_prefix = "Cipher: %-28s Vers: %-8s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
    print_result(result_prefix, ret)

    return ret


def handshake_test(host, port, test_ciphers):
    """
    Basic handshake tests using all valid combinations of supported cipher suites and TLS versions.
    """
    print("\n\tRunning s2n Client handshake tests:")

    failed = 0
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12, None]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        threadpool = create_thread_pool()
        port_offset = 0
        results = []

        for cipher in test_ciphers:
            async_result = threadpool.apply_async(run_handshake_test, (host, port + port_offset, ssl_version, cipher))
            port_offset += 1
            results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                failed = 1

    return failed

def handshake_resumption_test(host, port, no_ticket=False):
    """
    Basic handshake tests for session resumption.
    """
    if no_ticket:
        print("\n\tRunning s2n Client session resumption using session id tests:")
    else:
        print("\n\tRunning s2n Client session resumption using session ticket tests:")

    failed = 0
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12, None]:
        ret = try_handshake(host, port, None, ssl_version, resume=True, no_ticket=no_ticket)
        prefix = "Session Resumption for: %-40s ... " % (S2N_PROTO_VERS_TO_STR[ssl_version])
        print_result(prefix, ret)
        if ret != 0:
            failed = 1

    return failed

supported_sigs = ["RSA+SHA1", "RSA+SHA224", "RSA+SHA256", "RSA+SHA384", "RSA+SHA512"]
unsupported_sigs = ["ECDSA+SHA256", "ECDSA+SHA512"]


def run_sigalg_test(host, port, cipher, ssl_version, permutation):
    # Put some unsupported algs in front to make sure we gracefully skip them
    mixed_sigs = unsupported_sigs + list(permutation)
    mixed_sigs_str = ':'.join(mixed_sigs)
    ret = try_handshake(host, port, cipher.openssl_name, ssl_version, sig_algs=mixed_sigs_str)

    # Trim the RSA part off for brevity. User should know we are only supported RSA at the moment.
    prefix = "Digests: %-35s Vers: %-8s... " % (':'.join([x[4:] for x in permutation]), S2N_PROTO_VERS_TO_STR[S2N_TLS12])
    print_result(prefix, ret)
    return ret


def sigalg_test(host, port):
    """
    Acceptance test for supported signature algorithms. Tests all possible supported sigalgs with unsupported ones mixed in
    for noise.
    """
    failed = 0

    print("\n\tRunning s2n Client signature algorithm tests:")
    print("\tExpected supported:   " + str(supported_sigs))
    print("\tExpected unsupported: " + str(unsupported_sigs))

    for size in range(1, min(MAX_ITERATION_DEPTH, len(supported_sigs)) + 1):
        print("\n\t\tTesting ciphers using signature preferences of size: " + str(size))
        threadpool = create_thread_pool()
        portOffset = 0
        results = []
        # Produce permutations of every accepted signature algorithm in every possible order
        for permutation in itertools.permutations(supported_sigs, size):
            for cipher in ALL_TEST_CIPHERS:
                # Try an ECDHE cipher suite and a DHE one
                if cipher.openssl_name == "ECDHE-RSA-AES128-GCM-SHA256" or cipher.openssl_name == "DHE-RSA-AES128-GCM-SHA256":
                    async_result = threadpool.apply_async(run_sigalg_test, (host, port + portOffset, cipher, None, permutation))
                    portOffset = portOffset + 1
                    results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                failed = 1

    return failed


def elliptic_curve_test(host, port, libcrypto_version):
    """
    Acceptance test for supported elliptic curves. Tests all possible supported curves with unsupported curves mixed in
    for noise.
    """
    supported_curves = get_supported_curves_list_by_version(libcrypto_version)
    unsupported_curves = ["B-163", "K-409"]
    print("\n\tRunning s2n Client elliptic curve tests:")
    print("\tExpected supported:   " + str(supported_curves))
    print("\tExpected unsupported: " + str(unsupported_curves))

    failed = 0
    for size in range(1, min(MAX_ITERATION_DEPTH, len(supported_curves)) + 1):
        print("\n\t\tTesting ciphers using curve list of size: " + str(size))

        # Produce permutations of every accepted curve in every possible order
        for permutation in itertools.permutations(supported_curves, size):
            # Put some unsupported curves in front to make sure we gracefully skip them
            mixed_curves = unsupported_curves + list(permutation)
            mixed_curves_str = ':'.join(mixed_curves)
            for cipher in filter(lambda x: x.openssl_name == "ECDHE-RSA-AES128-GCM-SHA256" or x.openssl_name == "ECDHE-RSA-AES128-SHA", ALL_TEST_CIPHERS):
                ret = try_handshake(host, port, cipher.openssl_name, None, curves=mixed_curves_str)
                prefix = "Curves: %-40s Vers: %10s ... " % (':'.join(list(permutation)), S2N_PROTO_VERS_TO_STR[None])
                print_result(prefix, ret)
                if ret != 0:
                    failed = 1
    return failed

def main():
    parser = argparse.ArgumentParser(description='Runs TLS server integration tests against Openssl s_server using s2nc')
    parser.add_argument('host', help='The host for s2nc to connect to')
    parser.add_argument('port', type=int, help='The port for s_server to bind to')
    parser.add_argument('--use_corked_io', action='store_true', help='Turn corked IO on/off')
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=['openssl-1.0.2', 'openssl-1.0.2-fips', 'openssl-1.1.1', 'libressl'],
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
    args = parser.parse_args()
    use_corked_io = args.use_corked_io

    # Retrieve the test ciphers to use based on the libcrypto version s2n was built with
    test_ciphers = S2N_LIBCRYPTO_TO_TEST_CIPHERS[args.libcrypto]
    host = args.host
    port = args.port
    libcrypto_version = args.libcrypto

    print("\nRunning s2n Client tests with: " + os.popen('openssl version').read())
    if use_corked_io == True:
        print("Corked IO is on")

    failed = 0
    failed += handshake_test(host, port, test_ciphers)
    failed += handshake_resumption_test(host, port, no_ticket=True)
    failed += handshake_resumption_test(host, port)
    failed += sigalg_test(host, port)
    failed += elliptic_curve_test(host, port, libcrypto_version)
    return failed


if __name__ == "__main__":
    sys.exit(main())

