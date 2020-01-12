#
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# A container to make passing the return values from an attempted handshake more convenient
HANDSHAKE_RC = collections.namedtuple('HANDSHAKE_RC', 'handshake_success gnutls_stdout')

# Helper to print just the SHA256 portion of SIGN-RSA-SHA256
def sigalg_str_from_list(sigalgs):
    # strip the first nine bytes from each name for "SIGN-RSA", 11 for "SIGN-ECDSA"
    return ":".join(x[9:] if x.startswith("SIGN-RSA") else x[11:] for x in sigalgs)

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
    gnutls_cli = subprocess.Popen(gnutls_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Save the initial output of gnutls-cli to parse the negotiated handshake parameters later
    gnutls_initial_stdout_str = ""
    for line in range(0 , 100):
        output = gnutls_cli.stdout.readline().decode("utf-8")
        gnutls_initial_stdout_str += output + "\n"
        # Once we see this string, we have read enough output to determine which signature algorithm was used
        if "Simple Client Mode" in output:
            break

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
        return HANDSHAKE_RC(False, gnutls_initial_stdout_str)

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
        return HANDSHAKE_RC(False, gnutls_initial_stdout_str)

    gnutls_cli.kill()
    gnutls_cli.wait()
    s2nd.kill()
    s2nd.wait()
    return HANDSHAKE_RC(True, gnutls_initial_stdout_str)

def handshake(endpoint, port, cipher_name, ssl_version, priority_str, digests, mfl_extension_test, fips_mode,
        other_prefix=None):
    ret = try_gnutls_handshake(endpoint, port, priority_str, mfl_extension_test, fips_mode)

    prefix = other_prefix or ""
    if mfl_extension_test:
        prefix += "MFL: %-10s Cipher: %-10s Vers: %-10s ... " % (mfl_extension_test, cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
    elif len(digests) == 0:
        prefix += "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
    else:
        # strip the first nine bytes from each name for "SIGN-RSA", 11 for "SIGN-ECDSA"
        prefix += "Digests: %-40s Vers: %-10s ... " % (sigalg_str_from_list(digests), S2N_PROTO_VERS_TO_STR[ssl_version])

    suffix = ""
    if ret.handshake_success == True:
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
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=['openssl-1.0.2', 'openssl-1.0.2-fips', 'openssl-1.1.1', 'libressl'],
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
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
            if async_result.get().handshake_success == False:
                return -1

    # Produce permutations of every accepted signature algorithm in every possible order
    for size in range(1, min(MAX_ITERATION_DEPTH, len(EXPECTED_RSA_SIGNATURE_ALGORITHM_PREFS)) + 1):
        print("\n\tTesting ciphers using RSA signature preferences of size: " + str(size))
        threadpool = create_thread_pool()
        port_offset = 0
        results = []
        for permutation in itertools.permutations(EXPECTED_RSA_SIGNATURE_ALGORITHM_PREFS, size):
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
            if async_result.get().handshake_success == False:
                return -1

    # Try ECDSA signature algorithm permutations. When we support multiple certificates, we can combine the RSA and ECDSA tests
    for size in range(1, min(MAX_ITERATION_DEPTH, len(EXPECTED_ECDSA_SIGNATURE_ALGORITHM_PREFS)) + 1):
        print("\n\tTesting ciphers using ECDSA signature preferences of size: " + str(size))
        threadpool = create_thread_pool()
        port_offset = 0
        results = []
        for permutation in itertools.permutations(EXPECTED_ECDSA_SIGNATURE_ALGORITHM_PREFS, size):
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
            if async_result.get().handshake_success == False:
                return -1

    # Test that s2n's server Signature Algorithm preferences are as expected.
    # This is a brittle test that must be kept in sync with the signature algorithm preference lists in the core code,
    # but made manageable by rarity of signature algorithm preference updates.
    print("\n\tTesting RSA Signature Algorithm preferences")
    print("\n\tExpected preference order: " + ",".join(EXPECTED_RSA_SIGNATURE_ALGORITHM_PREFS))
    for i in range(0, len(EXPECTED_RSA_SIGNATURE_ALGORITHM_PREFS)):
        # To find the Nth preferred signature algorithm, generate a priority string with ALL sigalgs then subtract any
        # higher preference sigalgs we've already found.
        current_preferences_found = EXPECTED_RSA_SIGNATURE_ALGORITHM_PREFS[:i]
        # We expect to negotiate sigalg at preference i if previous i - 1 sigalgs are removed.
        expected_sigalg = EXPECTED_RSA_SIGNATURE_ALGORITHM_PREFS[i]
        for cipher in filter(lambda x: x.openssl_name == "ECDHE-RSA-AES128-SHA", ALL_TEST_CIPHERS):
            if fips_mode and cipher.openssl_fips_compatible == False:
                continue
            sig_algs_to_remove = ":!".join(current_preferences_found)
            sig_algs = "SIGN-ALL"
            if len(sig_algs_to_remove) > 0:
                sig_algs += ":!" + sig_algs_to_remove
            priority_str = cipher.gnutls_priority_str + ":+VERS-TLS1.2:+" + sig_algs
            rc = handshake(host, port, cipher.openssl_name, S2N_TLS12, priority_str, [], 0, fips_mode, "Preferences found: %-40s "
                    % (sigalg_str_from_list(current_preferences_found)))
            if rc.handshake_success == False:
                print("Failed to negotiate " + expected_sigalg + " as expected! Priority string: "
                        + priority_str)
                return -1
            negotiated_sigalg_line = [line for line in rc.gnutls_stdout.split('\n') if "Server Signature" in line]
            if len(negotiated_sigalg_line) == 0:
                print("Failed to find negotiated sig alg in gnutls-cli output! Priority string: " + priority_str)
                return -1

            # The gnutls-cli output is for sigalgs is of the format "Server Signature : $SIGALG"
            # Confusingly, $SIGALG is in GnuTLS priority string format with the "SIGN" part of the string removed.
            # Restore it to this string for comparison with existing list.
            negotiated_sigalg = "SIGN-" + negotiated_sigalg_line[0].split(":")[1].strip()
            if negotiated_sigalg != expected_sigalg:
                print("Failed to negotiate the expected sigalg! Expected " + expected_sigalg
                        + " Got: " + negotiated_sigalg + " at position " + str(i) + " in the preference list" +
                        " Priority string: " + priority_str)
                return -1

    print("\n\tTesting ECDSA Signature Algorithm preferences")
    print("\n\tExpected preference order: " + ",".join(EXPECTED_ECDSA_SIGNATURE_ALGORITHM_PREFS))
    for i in range(0, len(EXPECTED_ECDSA_SIGNATURE_ALGORITHM_PREFS)):
        # To find the Nth preferred signature algorithm, generate a priority string with ALL sigalgs then subtract any
        # higher preference sigalgs we've already found.
        current_preferences_found = EXPECTED_ECDSA_SIGNATURE_ALGORITHM_PREFS[:i]
        # We expect to negotiate sigalg at preference i if previous i - 1 sigalgs are removed.
        expected_sigalg = EXPECTED_ECDSA_SIGNATURE_ALGORITHM_PREFS[i]
        for cipher in filter(lambda x: x.openssl_name == "ECDHE-ECDSA-AES128-SHA", ALL_TEST_CIPHERS):
            if fips_mode and cipher.openssl_fips_compatible == False:
                continue
            sig_algs_to_remove = ":!".join(current_preferences_found)
            sig_algs = "SIGN-ALL"
            if len(sig_algs_to_remove) > 0:
                sig_algs += ":!" + sig_algs_to_remove
            priority_str = cipher.gnutls_priority_str + ":+VERS-TLS1.2:+" + sig_algs
            rc = handshake(host, port, cipher.openssl_name, S2N_TLS12, priority_str, [], 0, fips_mode, "Preferences found: %-40s "
                    % (sigalg_str_from_list(current_preferences_found)))
            if rc.handshake_success == False:
                print("Failed to negotiate " + expected_sigalg + " as expected! Priority string: " +
                        priority_str)
                return -1
            negotiated_sigalg_line = [line for line in rc.gnutls_stdout.split('\n') if "Server Signature" in line]
            if len(negotiated_sigalg_line) == 0:
                print("Failed to find negotiated sig alg in gnutls-cli output! Priority string: " + priority_str)
                return -1

            # The gnutls-cli output is for sigalgs is of the format "Server Signature : $SIGALG"
            # Confusingly, $SIGALG is in GnuTLS priority string format with the "SIGN" part of the string removed.
            # Restore it to this string for comparison with existing list.
            negotiated_sigalg = "SIGN-" + negotiated_sigalg_line[0].split(":")[1].strip()
            if negotiated_sigalg != expected_sigalg:
                print("Failed to negotiate the expected sigalg! Expected " + expected_sigalg
                        + " Got: " + negotiated_sigalg + " at position " + str(i) + " in the preference list" +
                        " Priority string: " + priority_str)
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
            if async_result.get().handshake_success == False:
                return -1

if __name__ == "__main__":
    sys.exit(main())
