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
Handshake tests using Openssl 0.9.8 s_client against s2nd
"""

import argparse
import os
import sys
import subprocess
import itertools
import multiprocessing
import threading
import uuid
import re
import string
from os import environ
from multiprocessing.pool import ThreadPool
from s2n_test_constants import *
from time import sleep

S_CLIENT_NEGOTIATED_CIPHER_PREFIX="Cipher    : "

PROTO_VERS_TO_S_CLIENT_ARG = {
    S2N_TLS10 : "-tls1",
    S2N_TLS11 : "-tls1_1",
    S2N_TLS12 : "-tls1_2",
}

use_corked_io=False

def cleanup_processes(*processes):
    for p in processes:
        p.kill()
        p.wait()

def validate_data_transfer(expected_data, s_client_out, s2nd_out):
    """
    Verify that the application data written between s_client and s2nd is encrypted and decrypted successfuly.
    """
    found = 0

    for line in s2nd_out.splitlines():
        if expected_data in line:
            found = 1
            break

    if found == 0:
        print ("Did not find " + expected_data + " in output from s2nd")
        return -1

    found = 0
    for line in s_client_out.splitlines():
        if expected_data in line:
            found = 1
            break

    if found == 0:
        print ("Did not find " + expected_data + " in output from s_client")
        return -1

    return 0

def find_expected_cipher(expected_cipher, s_client_out):
    """
    Make sure s_client and s2nd negotiate the cipher suite we expect
    """
    s_client_out_len = len(s_client_out)
    full_expected_string = S_CLIENT_NEGOTIATED_CIPHER_PREFIX + expected_cipher
    for line in s_client_out.splitlines():
        if full_expected_string in line:
            return 0
            break
    print("Failed to find " + expected_cipher + " in s_client output")
    return -1

def read_process_output_until(process, marker):
    output = ""

    while True:
        line = process.stdout.readline().decode("utf-8")
        output += line
        if marker in line:
            return output

    return output

def try_handshake(endpoint, port, cipher, ssl_version, server_name=None, strict_hostname=False, server_cert=None, server_key=None,
        server_cert_key_list=None, expected_server_cert=None, server_cipher_pref=None, ocsp=None, sig_algs=None, curves=None, resume=False, no_ticket=False,
        prefer_low_latency=False, enter_fips_mode=False, client_auth=None, client_cert=DEFAULT_CLIENT_CERT_PATH,
        client_key=DEFAULT_CLIENT_KEY_PATH, expected_cipher=None, expected_extensions=None):
    """
    Attempt to handshake against s2nd listening on `endpoint` and `port` using Openssl s_client
    :param int endpoint: endpoint for s2nd to listen on
    :param int port: port for s2nd to listen on
    :param str cipher: ciphers for Openssl s_client to offer. See https://www.openssl.org/docs/man1.0.2/apps/ciphers.html
    :param int ssl_version: SSL version for s_client to use
    :param str server_name: server_name value for s_client to send
    :param bool strict_hostname: whether s_client should strictly check to see if server certificate matches the server_name
    :param str server_cert: path to certificate for s2nd to use
    :param str server_key: path to private key for s2nd to use
    :param list server_cert_key_list: a list of (cert_path, key_path) tuples for multicert tests.
    :param str expected_server_cert: Path to the expected server certificate should be sent to s_client.
    :param str ocsp: path to OCSP response file for stapling
    :param str sig_algs: Signature algorithms for s_client to offer
    :param str curves: Elliptic curves for s_client to offer
    :param bool resume: True if s_client should try to reconnect to s2nd and reuse the same TLS session. False for normal negotiation.
    :param bool no_ticket: True if s2n server should not use session ticket to resume the same TLS session.
    :param bool prefer_low_latency: True if s2nd should use 1500 for max outgoing record size. False for default max.
    :param bool enter_fips_mode: True if s2nd should enter libcrypto's FIPS mode. Libcrypto must be built with a FIPS module to enter FIPS mode.
    :param bool client_auth: True if the test should try and use client authentication
    :param str client_cert: Path to the client's cert file
    :param str client_key: Path to the client's private key file
    :param str expected_cipher: the cipher we expect to negotiate
    :param list expected_extensions: list of expected extensions that s_client should receive.
    :return: 0 on successfully negotiation(s), -1 on failure
    """

    # Override certificate for ECDSA if unspecified. We can remove this when we
    # support multiple certificates
    if server_cert is None and server_cert_key_list is None and "ECDSA" in cipher:
        server_cert = TEST_ECDSA_CERT
        server_key = TEST_ECDSA_KEY

    # Fire up s2nd
    s2nd_cmd = ["../../bin/s2nd"]

    if server_cert is not None:
        s2nd_cmd.extend(["--cert", server_cert])
    if server_key is not None:
        s2nd_cmd.extend(["--key", server_key])
    if server_cert_key_list is not None:
        for cert_key_path in server_cert_key_list:
            cert_path = cert_key_path[0]
            key_path = cert_key_path[1]
            s2nd_cmd.extend(["--cert", cert_path])
            s2nd_cmd.extend(["--key", key_path])
    if ocsp is not None:
        s2nd_cmd.extend(["--ocsp", ocsp])
    if prefer_low_latency == True:
        s2nd_cmd.append("--prefer-low-latency")
    if client_auth is not None:
        s2nd_cmd.append("-m")
        s2nd_cmd.extend(["-t", client_cert])
    if use_corked_io:
        s2nd_cmd.append("-C")

    s2nd_cmd.extend([str(endpoint), str(port)])

    s2nd_ciphers = "test_all"
    if server_cipher_pref is not None:
        s2nd_ciphers = server_cipher_pref
    if enter_fips_mode == True:
        s2nd_ciphers = "test_all_fips"
        s2nd_cmd.append("--enter-fips-mode")
    s2nd_cmd.append("-c")
    s2nd_cmd.append(s2nd_ciphers)
    if no_ticket:
        s2nd_cmd.append("-T")

    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Make sure s2nd has started
    s2nd.stdout.readline()

    s_client_cmd = ["openssl", "s_client", "-connect", str(endpoint) + ":" + str(port)]

    if ssl_version is not None:
        s_client_cmd.append(PROTO_VERS_TO_S_CLIENT_ARG[ssl_version])
    if cipher is not None:
        s_client_cmd.extend(["-cipher", cipher])

    # For verifying extensions that s2nd sends expected extensions
    s_client_cmd.append("-tlsextdebug")

    # Fire up s_client
    s_client = subprocess.Popen(s_client_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    s_client_out = ""
    s2nd_out = ""

    openssl_connect_marker = "CONNECTED"
    openssl_reconnect_marker = "drop connection and then reconnect"
    end_of_msg_marker = "__end_of_msg__"

    # Wait until openssl and s2n have finished the handshake and are connected to each other
    s_client_out += read_process_output_until(s_client, openssl_connect_marker)
    s2nd_out += read_process_output_until(s2nd, openssl_connect_marker)

    if resume == True:
        for i in range(0,5):
            # Wait for openssl to resume connection 5 times in a row, and verify resumption works.
            s_client_out += read_process_output_until(s_client, openssl_reconnect_marker)
            s2nd_out += read_process_output_until(s2nd, openssl_connect_marker)

    data_to_validate = cipher + " " + str(uuid.uuid4())

    # Write the data to openssl towards s2n server
    msg = (data_to_validate + "\n" + end_of_msg_marker + "\n\n").encode("utf-8")
    s_client.stdin.write(msg)
    s_client.stdin.flush()

     # Write the data to s2n towards openssl client
    s2nd.stdin.write(msg)
    s2nd.stdin.flush()

    # Wait for the Data transfer to complete between OpenSSL and s2n
    s_client_out += read_process_output_until(s_client, end_of_msg_marker)
    s2nd_out += read_process_output_until(s2nd, end_of_msg_marker)

    cleanup_processes(s2nd, s_client)

    if validate_data_transfer(data_to_validate, s_client_out, s2nd_out) != 0:
        return -1

    if resume is True:
        if validate_resume(s2nd_out) != 0:
            return -1

    if ocsp is not None:
        if validate_ocsp(s_client_out) != 0:
            return -1

    if expected_cipher is not None:
        if find_expected_cipher(expected_cipher, s_client_out) != 0:
            return -1

    if strict_hostname is True:
        if validate_hostname(s_client_out) != 0:
            return -1

    if expected_server_cert is not None:
        if validate_selected_certificate(s_client_out, expected_server_cert) != 0:
            return -1

    if expected_extensions is not None:
        for extension in expected_extensions:
            if extension.s_client_validate(s_client_out) != 0:
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
    threadpool_size = multiprocessing.cpu_count() * 4  # Multiply by 4 to increase parallelization between integration tests
    print("\tCreating ThreadPool of size: " + str(threadpool_size))
    threadpool = ThreadPool(processes=threadpool_size)
    return threadpool

def run_handshake_test(host, port, ssl_version, cipher, fips_mode, no_ticket, use_client_auth, client_cert_path, client_key_path):
    cipher_name = cipher.openssl_name
    cipher_vers = cipher.min_tls_vers

    # Skip the cipher if openssl can't test it. 3DES/RC4 are disabled by default in 1.1.1
    if not cipher.openssl_1_1_1_compatible:
        return 0

    if ssl_version and ssl_version < cipher_vers:
        return 0

    client_cert_str=str(use_client_auth)

    if (use_client_auth is not None) and (client_cert_path is not None):
        client_cert_str = cert_path_to_str(client_cert_path)

    ret = try_handshake(host, port, cipher_name, ssl_version, no_ticket=no_ticket, enter_fips_mode=fips_mode, client_auth=use_client_auth, client_cert=client_cert_path, client_key=client_key_path)

    result_prefix = "Cipher: %-30s ClientCert: %-16s Vers: %-8s ... " % (cipher_name, client_cert_str, S2N_PROTO_VERS_TO_STR[ssl_version])
    print_result(result_prefix, ret)

    return ret

def handshake_test(host, port, test_ciphers, fips_mode, no_ticket=False, use_client_auth=None, use_client_cert=None, use_client_key=None):
    """
    Basic handshake tests using all valid combinations of supported cipher suites and TLS versions.
    """
    print("\n\tRunning handshake tests:")

    failed = 0
    for ssl_version in [S2N_TLS10,  None]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        port_offset = 0
        results = []

        # Only test non ECC ciphers, openssl 0.9.8 has trouble with ECDHE.
        # Only test 1.0/SSLv3 ciphers since 0.9.8 only supports those.
        for cipher in filter(lambda x: "ECDHE" not in x.openssl_name and x.min_tls_vers < S2N_TLS11, test_ciphers):
            async_result = run_handshake_test(host, port + port_offset, ssl_version, cipher, fips_mode, no_ticket, use_client_auth, use_client_cert, use_client_key)
            port_offset += 1
            results.append(async_result)

        for async_result in results:
            if async_result != 0:
                failed = 1

    return failed

def main():
    parser = argparse.ArgumentParser(description='Runs TLS server integration tests against s2nd using Openssl s_client')
    parser.add_argument('host', help='The host for s2nd to bind to')
    parser.add_argument('port', type=int, help='The port for s2nd to bind to')
    parser.add_argument('--use_corked_io', action='store_true', help='Turn corked IO on/off')
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=S2N_LIBCRYPTO_CHOICES,
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
    args = parser.parse_args()
    use_corked_io = args.use_corked_io

    # Retrieve the test ciphers to use based on the libcrypto version s2n was built with
    test_ciphers = S2N_LIBCRYPTO_TO_TEST_CIPHERS[args.libcrypto]
    host = args.host
    port = args.port
    libcrypto_version = args.libcrypto

    fips_mode = False
    if environ.get("S2N_TEST_IN_FIPS_MODE") is not None:
        fips_mode = True
        print("\nRunning s2nd in FIPS mode.")

    print("\nRunning tests with: " + os.popen('openssl version').read())
    if use_corked_io == True:
        print("Corked IO is on")

    failed = 0
    failed += handshake_test(host, port, test_ciphers, fips_mode)

    return failed

if __name__ == "__main__":
    sys.exit(main())

