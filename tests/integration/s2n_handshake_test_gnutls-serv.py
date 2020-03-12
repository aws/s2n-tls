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
Simple handshake tests using gnutls-serv
"""

import argparse
import collections
import os
import sys
import ssl
import socket
import subprocess
import itertools
import multiprocessing
from os import environ
from multiprocessing.pool import ThreadPool
from s2n_test_constants import *

def try_gnutls_handshake(endpoint, port, priority_str, session_tickets, ocsp):
    gnutls_cmd = ["gnutls-serv", "--priority=" + priority_str, "-p " + str(port),
            "--dhparams", TEST_DH_PARAMS]

    if "ECDSA" in priority_str:
        ocsp_response = TEST_OCSP_ECDSA_RESPONSE_FILE

        # When gnutls-serv is provided with incorrect staple, it'll indicate
        # that it's going to send an OCSP response through ServerHello
        # extension, but it won't send the ServerCertStatus message.
        if ocsp == OCSP.MALFORMED:
            ocsp_response = TEST_OCSP_RESPONSE_FILE

        gnutls_cmd.extend(["--x509keyfile", TEST_OCSP_ECDSA_KEY, "--x509certfile", TEST_OCSP_ECDSA_CERT,
            "--ocsp-response", ocsp_response])
    else:
        ocsp_response = TEST_OCSP_RESPONSE_FILE

        if ocsp == OCSP.MALFORMED:
            ocsp_response = TEST_OCSP_ECDSA_RESPONSE_FILE

        gnutls_cmd.extend(["--x509keyfile", TEST_OCSP_KEY, "--x509certfile", TEST_OCSP_CERT,
            "--ocsp-response", ocsp_response])

    if not session_tickets:
        gnutls_cmd.append("--noticket")

    # Fire up gnutls-serv
    gnutls_serv = subprocess.Popen(gnutls_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Make sure it's running
    gnutls_serv.stderr.readline()

    # Fire up s2nc
    s2nc_cipher_suite = "test_all"
    if "ECDSA" in priority_str:
        s2nc_cipher_suite = "test_all_ecdsa"

    s2nc_cmd = ["../../bin/s2nc", "-i", "-r", "-c", s2nc_cipher_suite, str(endpoint), str(port)]

    if ocsp != OCSP.DISABLED:
        s2nc_cmd.append("-s")

    s2nc = subprocess.Popen(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Read it
    found = 0
    for line in range(0, 50):
        output = s2nc.stdout.readline().decode("utf-8")
        if output.strip().startswith("Connected to"):
            found = 1
            break

    gnutls_serv.kill()
    gnutls_serv.communicate()
    gnutls_serv.wait()

    s2nc.kill()
    s2nc.communicate()
    s2nc.wait()

    return found == 1

def handshake(endpoint, port, cipher, session_tickets, ocsp):
    success = try_gnutls_handshake(endpoint, port, cipher.gnutls_priority_str + ":+VERS-TLS1.2:+SIGN-ALL:+SHA1", session_tickets, ocsp)

    prefix = "Cipher: %-30s Session Tickets: %-5s OCSP: %-5s ... " % (cipher.openssl_name, session_tickets, ocsp)

    suffix = ""
    if success:
        if sys.stdout.isatty():
            suffix = "\033[32;1mPASSED\033[0m"
        else:
            suffix = "PASSED"
    else:
        if sys.stdout.isatty():
            suffix = "\033[31;1mFAILED\033[0m"
        else:
            suffix = "FAILED"
    print(prefix + suffix)
    return success


def create_thread_pool():
    threadpool_size = multiprocessing.cpu_count() * 2  #Multiply by 2 since performance improves slightly if CPU has hyperthreading
    print("\n\tCreating ThreadPool of size: " + str(threadpool_size))
    threadpool = ThreadPool(processes=threadpool_size)
    return threadpool


def main():
    parser = argparse.ArgumentParser(description='Runs TLS server integration tests against s2nd using gnutls-cli')
    parser.add_argument('host', help='The host for gnutls-serv to bind to')
    parser.add_argument('port', type=int, help='The port for gnutls-serv to bind to')
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=S2N_LIBCRYPTO_CHOICES,
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
    args = parser.parse_args()

    # Retrieve the test ciphers to use based on the libcrypto version s2n was built with
    test_ciphers = S2N_LIBCRYPTO_TO_TEST_CIPHERS[args.libcrypto]
    host = args.host
    port = args.port

    print("\nRunning GnuTLS handshake tests with: " + os.popen('gnutls-serv --version | grep -w gnutls-serv').read())

    # gnutls-serv requests cient cert by default, but allows empty cert to be
    # provided, test that this functionality work with and without session
    # tickets for all cipher suites and handshakes with and without OCSP staple
    threadpool = create_thread_pool()
    port_offset = 0
    results = []
    for cipher in test_ciphers:
        for session_tickets in [True, False]:
            for ocsp in S2N_LIBCRYPTO_TO_OCSP[args.libcrypto]:
                async_result = threadpool.apply_async(handshake, (host, port + port_offset, cipher, session_tickets, ocsp))
                port_offset += 1
                results.append(async_result)
    threadpool.close()
    threadpool.join()
    for async_result in results:
        if not async_result.get():
            return -1

    return 0

if __name__ == "__main__":
    sys.exit(main())
