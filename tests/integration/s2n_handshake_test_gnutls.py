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

import argparse
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

def try_gnutls_handshake(endpoint, port, priority_str, mfl_extension_test, enter_fips_mode=False):
    # Fire up s2nd
    s2nd_cmd = ["../../bin/s2nd", str(endpoint), str(port)]
    s2nd_ciphers = "test_all"

    if enter_fips_mode == True:
        s2nd_ciphers = "test_all_fips"
        s2nd_cmd.append("--enter-fips-mode")
    s2nd_cmd.append("-c")
    s2nd_cmd.append(s2nd_ciphers)
    if "ECDSA" in priority_str:
        s2nd_ciphers = "test_all_ecdsa"
        s2nd_cmd.extend(["--cert", TEST_ECDSA_CERT])
        s2nd_cmd.extend(["--key", TEST_ECDSA_KEY])
    if mfl_extension_test:
        s2nd_cmd.append("--enable-mfl")
    
    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Make sure it's running
    s2nd.stdout.readline()

    gnutls_cmd = ["gnutls-cli", "--priority=" + priority_str,"--insecure", "-p " + str(port), str(endpoint)]

    if mfl_extension_test:
        gnutls_cmd.append("--recordsize=" + str(mfl_extension_test))
 
    # Fire up gnutls-cli, use insecure since s2nd is using a dummy cert
    gnutls_cli = subprocess.Popen(gnutls_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

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

def handshake(endpoint, port, cipher_name, ssl_version, priority_str, digests, mfl_extension_test, fips_mode):
    ret = try_gnutls_handshake(endpoint, port, priority_str, mfl_extension_test, fips_mode)

    prefix = ""
    if mfl_extension_test:
        prefix = "MFL: %-10s Cipher: %-10s Vers: %-10s ... " % (mfl_extension_test, cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
    elif len(digests) == 0:
        prefix = "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
    else:
        # strip the first nine bytes from each name ("RSA-SIGN-")
        digest_string = ':'.join([x[9:] for x in digests])
        prefix = "Digests: %-40s Vers: %-10s ... " % (digest_string, S2N_PROTO_VERS_TO_STR[ssl_version])

    suffix = ""
    if ret == 0:
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
    return ret

def create_thread_pool():
    threadpool_size = multiprocessing.cpu_count() * 2  #Multiply by 2 since performance improves slightly if CPU has hyperthreading
    print("\n\tCreating ThreadPool of size: " + str(threadpool_size))
    threadpool = ThreadPool(processes=threadpool_size)
    return threadpool

def main():
    parser = argparse.ArgumentParser(description='Runs TLS server integration tests against s2nd using gnutls-cli')
    parser.add_argument('host', help='The host for s2nd to bind to')
    parser.add_argument('port', type=int, help='The port for s2nd to bind to')
    parser.add_argument('--libcrypto', default='openssl-1.1.0', choices=['openssl-1.0.2', 'openssl-1.0.2-fips', 'openssl-1.1.0', 'openssl-1.1.x-master', 'libressl'],
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.0.""")
    args = parser.parse_args()

    # Retrieve the test ciphers to use based on the libcrypto version s2n was built with
    test_ciphers = S2N_LIBCRYPTO_TO_TEST_CIPHERS[args.libcrypto]
    host = args.host
    port = args.port

    fips_mode = False
    if environ.get("S2N_TEST_IN_FIPS_MODE") is not None:
        fips_mode = True
        print("\nRunning s2nd in FIPS mode.")

    print("\nRunning GnuTLS handshake tests with: " + os.popen('gnutls-cli --version | grep -w gnutls-cli').read())
    for ssl_version in [S2N_SSLv3, S2N_TLS10, S2N_TLS11, S2N_TLS12]:

        if ssl_version == S2N_SSLv3 and fips_mode == True:
            # FIPS does not permit the use of SSLv3
            continue

        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        threadpool = create_thread_pool()
        port_offset = 0
        results = []

        for cipher in test_ciphers:
            # Use the Openssl name for printing
            cipher_name = cipher.openssl_name
            cipher_priority_str = cipher.gnutls_priority_str
            cipher_vers = cipher.min_tls_vers

            if ssl_version < cipher_vers:
                continue

            # gnutls-cli always adds tls extensions to client hello, add NO_EXTENSIONS flag for SSLv3 to avoid that
            if ssl_version == S2N_SSLv3:
                cipher_priority_str = cipher_priority_str + ":%NO_EXTENSIONS"

            # Add the SSL version to make the cipher priority string fully qualified
            complete_priority_str = cipher_priority_str + ":+" + S2N_PROTO_VERS_TO_GNUTLS[ssl_version] + ":+SIGN-ALL"

            async_result = threadpool.apply_async(handshake, (host, port + port_offset, cipher_name, ssl_version, complete_priority_str, [], 0, fips_mode))
            port_offset += 1
            results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                return -1

    # Produce permutations of every accepted signature algorithm in every possible order
    rsa_signatures = ["SIGN-RSA-SHA1", "SIGN-RSA-SHA224", "SIGN-RSA-SHA256", "SIGN-RSA-SHA384", "SIGN-RSA-SHA512"];
    
    for size in range(1, len(rsa_signatures) + 1):
        print("\n\tTesting ciphers using signature preferences of size: " + str(size))
        threadpool = create_thread_pool()
        port_offset = 0
        results = []
        for permutation in itertools.permutations(rsa_signatures, size):
            # Try an ECDHE cipher suite and a DHE one
            for cipher in filter(lambda x: x.openssl_name == "ECDHE-RSA-AES128-GCM-SHA256" or x.openssl_name == "DHE-RSA-AES128-GCM-SHA256", ALL_TEST_CIPHERS):
                if fips_mode and cipher.openssl_fips_compatible == False:
                    continue
                complete_priority_str = cipher.gnutls_priority_str + ":+VERS-TLS1.2:+" + ":+".join(permutation)
                async_result = threadpool.apply_async(handshake,(host, port + port_offset, cipher.openssl_name, S2N_TLS12, complete_priority_str, permutation, 0, fips_mode))
                port_offset += 1
                results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                return -1
   
    # Try ECDSA signature algorithm permutations. When we support multiple certificates, we can combine the RSA and ECDSA tests
    ecdsa_signatures = ["SIGN-ECDSA-SHA1", "SIGN-ECDSA-SHA224", "SIGN-ECDSA-SHA256", "SIGN-ECDSA-SHA384", "SIGN-ECDSA-SHA512"];
    for size in range(1, len(ecdsa_signatures) + 1):
        print("\n\tTesting ciphers using ECDSA signature preferences of size: " + str(size))
        threadpool = create_thread_pool()
        port_offset = 0
        results = []
        for permutation in itertools.permutations(ecdsa_signatures, size):
            for cipher in filter(lambda x: x.openssl_name == "ECDHE-ECDSA-AES128-SHA", ALL_TEST_CIPHERS):
                if fips_mode and cipher.openssl_fips_compatible == False:
                    continue
                complete_priority_str = cipher.gnutls_priority_str + ":+VERS-TLS1.2:+" + ":+".join(permutation)
                async_result = threadpool.apply_async(handshake,(host, port + port_offset, cipher.openssl_name, S2N_TLS12, complete_priority_str, permutation, 0, fips_mode))
                port_offset += 1
                results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                return -1

    print("\n\tTesting handshakes with Max Fragment Length Extension")
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12]:
        print("\n\tTesting Max Fragment Length Extension using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        threadpool = create_thread_pool()
        port_offset = 0
        results = []
        for mfl_extension_test in [512, 1024, 2048, 4096]:
            cipher = test_ciphers[0]
            complete_priority_str = cipher.gnutls_priority_str + ":+" + S2N_PROTO_VERS_TO_GNUTLS[ssl_version] + ":+SIGN-ALL"
            async_result = threadpool.apply_async(handshake,(host, port + port_offset, cipher.openssl_name, ssl_version, complete_priority_str, [], mfl_extension_test, fips_mode))
            port_offset += 1
            results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                return -1


if __name__ == "__main__":
    sys.exit(main())
