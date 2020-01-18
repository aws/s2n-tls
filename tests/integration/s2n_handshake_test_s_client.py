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
Handshake tests using Openssl s_client against s2nd
Openssl 1.1.0 removed SSLv3, 3DES, an RC4, so we won't have coverage there.
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

PROTO_VERS_TO_S_CLIENT_ARG = {
    S2N_TLS10 : "-tls1",
    S2N_TLS11 : "-tls1_1",
    S2N_TLS12 : "-tls1_2",
}

S_CLIENT_SUCCESSFUL_OCSP="OCSP Response Status: successful"
S_CLIENT_NEGOTIATED_CIPHER_PREFIX="Cipher    : "
S_CLIENT_HOSTNAME_MISMATCH="verify error:num=62:Hostname mismatch"
# Server certificate starts on the line after this one.
S_CLIENT_START_OF_SERVER_CERTIFICATE="Server certificate"
S_CLIENT_LAST_CERTIFICATE_LINE_PATTERN=re.compile("-----END.*CERTIFICATE-----")
S_CLIENT_SERVER_NAME_EXTENSION='TLS server extension "server name"'

class TlsExtensionServerName:
    def s_client_validate(s_client_out):
        s_client_out_len = len(s_client_out)
        for line in s_client_out.splitlines():
            if S_CLIENT_SERVER_NAME_EXTENSION in line:
                return 0
        print("Did not find the ServerName extension as expected!")

        return -1

use_corked_io=False

def get_supported_curves_list_by_version(libcrypto_version):
   # Curve X25519 is supported for Openssl 1.1.0 and higher
    if libcrypto_version == "openssl-1.1.1":
        return  ["P-256", "P-384", "X25519"]
    else:
        return  ["P-256", "P-384"]

def get_supported_curves_str_by_version(libcrypto_version):
   # Curve X25519 is supported for Openssl 1.1.0 and higher
    if libcrypto_version == "openssl-1.1.1":
        return "P-256:P-384:X25519"
    else:
        return "P-256:P-384"

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

def validate_resume(s2nd_out):
    """
    Verify that s2nd properly resumes sessions.
    """
    resume_count = 0

    for line in s2nd_out.splitlines():
        if line.startswith("Resumed session"):
            resume_count += 1

        if resume_count == 5:
            break

    if resume_count != 5:
        print ("Validate resumption failed")
        return -1

    return 0

def validate_ocsp(s_client_out):
    """
    Verify that stapled OCSP response is accepted by s_client.
    """
    s_client_out_len = len(s_client_out)
    for line in s_client_out.splitlines():
        if S_CLIENT_SUCCESSFUL_OCSP in line:
            return 0
            break
    print ("Validate OCSP failed")
    return -1

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

def validate_hostname(s_client_out):
    """
    Make sure that s_client did not error on hostname mismatch.
    This function is only valid if s_client output was invoked with "-verify_hostname" argument
    """
    s_client_out_len = len(s_client_out)
    for line in s_client_out.splitlines():
        if S_CLIENT_HOSTNAME_MISMATCH in line:
            print("Server certificate hostname did not match client server_name")
            return 1
    return 0

def validate_selected_certificate(s_client_out, expected_cert_path):
    """
    Make sure that the server certificate that s_client sees is the certificate we expect.
    """
    s_client_out_len = len(s_client_out)
    start_found = 0
    cert_str = ""
    for line in s_client_out.splitlines():
        # Spin until we get to the start of the cert
        if start_found == 0:
            if S_CLIENT_START_OF_SERVER_CERTIFICATE in line:
                start_found = 1
        else:
            cert_str+=line
            cert_str+="\n"
        # reached the end of the cert.
        if S_CLIENT_LAST_CERTIFICATE_LINE_PATTERN.match(line):
            break

    expected_cert_str = open(expected_cert_path).read()
    if "".join(cert_str.split()) != "".join(expected_cert_str.split()):
        print("The expected certificate was not served!!!")
        print("The cert I expected: \n" + expected_cert_str)
        print("The cert I got: \n" + cert_str)
        return -1

    return 0

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
    if use_corked_io:
        s2nd_cmd.append("-C")

    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Make sure s2nd has started
    s2nd.stdout.readline()

    s_client_cmd = ["openssl", "s_client", "-connect", str(endpoint) + ":" + str(port)]

    if ssl_version is not None:
        s_client_cmd.append(PROTO_VERS_TO_S_CLIENT_ARG[ssl_version])
    if cipher is not None:
        s_client_cmd.extend(["-cipher", cipher])
    if sig_algs is not None:
        s_client_cmd.extend(["-sigalgs", sig_algs])
    if curves is not None:
        s_client_cmd.extend(["-curves", curves])
    if resume == True:
        s_client_cmd.append("-reconnect")
    if client_auth is not None:
        s_client_cmd.extend(["-key", client_key])
        s_client_cmd.extend(["-cert", client_cert])
    if ocsp is not None:
        s_client_cmd.append("-status")
    if server_name is not None:
        s_client_cmd.extend(["-servername", server_name])
        if strict_hostname is True:
            s_client_cmd.extend(["-verify_hostname", server_name])
    else:
        s_client_cmd.append("-noservername")

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
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12, None]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        threadpool = create_thread_pool()
        port_offset = 0
        results = []
        
        for cipher in test_ciphers:
            async_result = threadpool.apply_async(run_handshake_test, (host, port + port_offset, ssl_version, cipher, fips_mode, no_ticket, use_client_auth, use_client_cert, use_client_key))
            port_offset += 1
            results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                failed = 1

    return failed
    

def client_auth_test(host, port, test_ciphers, fips_mode):
    failed = 0

    print("\n\tRunning client auth tests:")

    for filename in os.listdir(TEST_CERT_DIRECTORY):
        if "client_cert" in filename and "rsa" in filename:
            client_cert_path = TEST_CERT_DIRECTORY + filename
            client_key_path = TEST_CERT_DIRECTORY + filename.replace("client_cert", "client_key")
            ret = handshake_test(host, port, test_ciphers, fips_mode, no_ticket=True, use_client_auth=True, use_client_cert=client_cert_path, use_client_key=client_key_path)
            if ret is not 0:
                failed += 1
                
    return failed

def run_resume_test(host, port, cipher_name, ssl_version, resume, no_ticket, fips_mode):
    ret = try_handshake(host, port, cipher_name, ssl_version, resume=resume, no_ticket=no_ticket, enter_fips_mode=fips_mode)
    result_prefix = "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
    print_result(result_prefix, ret)

    return ret

def resume_test(host, port, test_ciphers, fips_mode, no_ticket=False):
    """
    Tests s2n's session resumption capability using all valid combinations of cipher suite and TLS version.
    """
    if no_ticket:
        print("\n\tRunning resumption tests using session id:")
    else:
        print("\n\tRunning resumption tests using session ticket:")

    failed = 0
    results = []
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12, None]:
        port_offset = 0
        threadpool = create_thread_pool()
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        for cipher in test_ciphers:
            cipher_name = cipher.openssl_name
            cipher_vers = cipher.min_tls_vers

            # Skip the cipher if openssl can't test it. 3DES/RC4 are disabled by default in 1.1.1
            if not cipher.openssl_1_1_1_compatible:
                continue

            if ssl_version and ssl_version < cipher_vers:
                continue

            async_result = threadpool.apply_async(run_resume_test, (host, port + port_offset, cipher_name, ssl_version, True, no_ticket, fips_mode))
            port_offset += 1
            results.append(async_result)

        threadpool.close()
        threadpool.join()

        for async_result in results:
            if async_result.get() != 0:
                failed = 1

    return failed

supported_sigs = ["RSA+SHA1", "RSA+SHA224", "RSA+SHA256", "RSA+SHA384", "RSA+SHA512"]
unsupported_sigs = ["ECDSA+SHA256", "ECDSA+SHA512"]

def run_sigalg_test(host, port, cipher, ssl_version, permutation, fips_mode, use_client_auth, no_ticket):
    # Put some unsupported algs in front to make sure we gracefully skip them
    mixed_sigs = unsupported_sigs + list(permutation)
    mixed_sigs_str = ':'.join(mixed_sigs)
    ret = try_handshake(host, port, cipher.openssl_name, ssl_version, sig_algs=mixed_sigs_str, no_ticket=no_ticket, enter_fips_mode=fips_mode, client_auth=use_client_auth)
        
    # Trim the RSA part off for brevity. User should know we are only supported RSA at the moment.
    prefix = "Digests: %-35s ClientAuth: %-6s Vers: %-8s... " % (':'.join([x[4:] for x in permutation]), str(use_client_auth), S2N_PROTO_VERS_TO_STR[ssl_version])
    print_result(prefix, ret)
    return ret

def sigalg_test(host, port, fips_mode, use_client_auth=None, no_ticket=False):
    """
    Acceptance test for supported signature algorithms. Tests all possible supported sigalgs with unsupported ones mixed in
    for noise.
    """
    failed = 0

    print("\n\tRunning signature algorithm tests:")
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
                if (cipher.openssl_name == "ECDHE-RSA-AES128-GCM-SHA256" or cipher.openssl_name == "DHE-RSA-AES128-GCM-SHA256"):
                    async_result = threadpool.apply_async(run_sigalg_test, (host, port + portOffset, cipher, None, permutation, fips_mode, use_client_auth, no_ticket))
                    portOffset = portOffset + 1
                    results.append(async_result)

        threadpool.close()
        threadpool.join()
        for async_result in results:
            if async_result.get() != 0:
                failed = 1

    return failed

def elliptic_curve_test(host, port, libcrypto_version, fips_mode):
    """
    Acceptance test for supported elliptic curves. Tests all possible supported curves with unsupported curves mixed in
    for noise.
    """
    supported_curves = get_supported_curves_list_by_version(libcrypto_version)
    unsupported_curves = ["B-163", "K-409"]
    print("\n\tRunning elliptic curve tests:")
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
                if fips_mode and cipher.openssl_fips_compatible == False:
                    continue
                ret = try_handshake(host, port, cipher.openssl_name, None, curves=mixed_curves_str, enter_fips_mode=fips_mode)
                prefix = "Curves: %-40s Vers: %10s ... " % (':'.join(list(permutation)), S2N_PROTO_VERS_TO_STR[None])
                print_result(prefix, ret)
                if ret != 0:
                    failed = 1
    return failed

def elliptic_curve_fallback_test(host, port, fips_mode):
    """
    Tests graceful fallback when s2n doesn't support any curves offered by the client. A non-ecc suite should be
    negotiated.
    """
    failed = 0
    # Make sure s2n can still negotiate a non-EC kx(AES256-GCM-SHA384) suite if we don't match anything on the client
    unsupported_curves = ["B-163", "K-409"]
    ret = try_handshake(host, port, "ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384", None, curves=":".join(unsupported_curves), enter_fips_mode=fips_mode)
    print_result("%-65s ... " % "Testing curve mismatch fallback", ret)
    if ret != 0:
        failed = 1

    return failed

def handshake_fragmentation_test(host, port, fips_mode):
    """
    Tests successful negotation with s_client despite message fragmentation. Max record size is clamped to force s2n
    to fragment the ServerCertifcate message.
    """
    print("\n\tRunning handshake fragmentation tests:")
    failed = 0
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12, None]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        # Cipher isn't relevant for this test, pick one available in all OpenSSL versions and all TLS versions
        cipher_name = "AES256-SHA"

        # Low latency option indirectly forces fragmentation.
        ret = try_handshake(host, port, cipher_name, ssl_version, prefer_low_latency=True, enter_fips_mode=fips_mode)
        result_prefix = "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
        print_result(result_prefix, ret)
        if ret != 0:
            failed = 1

    failed = 0
    return failed

def ocsp_stapling_test(host, port, fips_mode):
    """
    Test s2n's server OCSP stapling capability
    """
    print("\n\tRunning OCSP stapling tests:")
    failed = 0
    for ssl_version in [S2N_TLS10, S2N_TLS11, S2N_TLS12, None]:
        print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
        # Cipher isn't relevant for this test, pick one available in all TLS versions
        cipher_name = "AES256-SHA"

        ret = try_handshake(host, port, cipher_name, ssl_version, enter_fips_mode=fips_mode, server_cert=TEST_OCSP_CERT, server_key=TEST_OCSP_KEY,
                ocsp=TEST_OCSP_RESPONSE_FILE)
        result_prefix = "Cipher: %-30s Vers: %-10s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
        print_result(result_prefix, ret)
        if ret != 0:
            failed = 1

    return failed

def cert_type_cipher_match_test(host, port, libcrypto_version):
    """
    Test s2n server's ability to correctly choose ciphers. (Especially RSA vs ECDSA)
    """
    print("\n\tRunning cipher matching tests:")
    failed = 0

    cipher = "ALL"
    supported_curves = get_supported_curves_str_by_version(libcrypto_version)

    # Handshake with RSA cert + ECDSApriority server cipher pref (must skip ecdsa ciphers)
    rsa_ret = try_handshake(host, port, cipher, None, curves=supported_curves,
            server_cipher_pref="test_ecdsa_priority")
    result_prefix = "Cert Type: rsa    Server Pref: ecdsa priority.  Vers: %-10s ... " % S2N_PROTO_VERS_TO_STR[None]
    print_result(result_prefix, rsa_ret)
    if rsa_ret != 0:
        failed = 1

    # Handshake with ECDSA cert + RSA priority server cipher prefs (must skip rsa ciphers)
    ecdsa_ret = try_handshake(host, port, cipher, None, curves=supported_curves,
            server_cert=TEST_ECDSA_CERT, server_key=TEST_ECDSA_KEY, server_cipher_pref="test_all")
    result_prefix = "Cert Type: ecdsa  Server Pref: rsa priority.  Vers: %-10s ... " % S2N_PROTO_VERS_TO_STR[None]
    print_result(result_prefix, ecdsa_ret)
    if ecdsa_ret != 0:
        failed = 1

    return failed

def multiple_cert_type_test(host, port, libcrypto_version):
    """
    Test s2n server's ability to correctly choose ciphers and serve the correct cert depending on the auth type for a
    given cipher.
    """
    print("\n\tRunning multiple server cert type test:")

    # Basic handshake with ECDSA cert + RSA cert
    for cipher in ["ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-GCM-SHA256"]:
        supported_curves = get_supported_curves_str_by_version(libcrypto_version)
        server_prefs = "test_all"
        ret = try_handshake(host, port, cipher, None, curves=supported_curves,
                server_cert_key_list=[(TEST_RSA_CERT, TEST_RSA_KEY),(TEST_ECDSA_CERT, TEST_ECDSA_KEY)],
                server_cipher_pref=server_prefs)
        result_prefix = "Certs: [RSA, ECDSA]  Client Prefs %s Server Pref: %s Vers: %-10s ... " % (cipher, server_prefs, S2N_PROTO_VERS_TO_STR[None])
        print_result(result_prefix, ret)
        if ret != 0:
            return ret

    # Handshake with ECDSA + RSA cert but no ecdsa ciphers configured on the server
    for cipher in ["ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA"]:
        supported_curves = get_supported_curves_str_by_version(libcrypto_version)
        server_prefs = "20170210"
        ret = try_handshake(host, port, cipher, None, curves=supported_curves,
                server_cert_key_list=[(TEST_RSA_CERT, TEST_RSA_KEY),(TEST_ECDSA_CERT, TEST_ECDSA_KEY)],
                server_cipher_pref=server_prefs)
        result_prefix = "Certs: [RSA, ECDSA]  Client Prefs %s Server Pref: %s Vers: %-10s ... " % (cipher, server_prefs, S2N_PROTO_VERS_TO_STR[None])
        print_result(result_prefix, ret)
        if ret != 0:
            return ret

    # Handshake with ECDSA + RSA cert but no rsa ciphers configured on the server
    for cipher in ["ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-SHA"]:
        supported_curves = get_supported_curves_str_by_version(libcrypto_version)
        server_prefs = "test_all_ecdsa"
        ret = try_handshake(host, port, cipher, None, curves=supported_curves,
                server_cert_key_list=[(TEST_RSA_CERT, TEST_RSA_KEY),(TEST_ECDSA_CERT, TEST_ECDSA_KEY)],
                server_cipher_pref=server_prefs)
        result_prefix = "Certs: [RSA, ECDSA]  Client Prefs %s Server Pref: %s Vers: %-10s ... " % (cipher, server_prefs, S2N_PROTO_VERS_TO_STR[None])
        print_result(result_prefix, ret)
        if ret != 0:
            return ret

    # Handshake with ECDSA + RSA cert but no overlapping ecc curves for ECDHE kx.
    # s2n should fallback to a cipher with RSA kx.
    for cipher in ["ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:AES128-SHA", "ECDHE-ECDSA-AES256-SHA:AES128-SHA"]:
        # Assume this is a curve s2n does not support
        supported_curves = "P-521"
        server_prefs = "test_all"
        ret = try_handshake(host, port, cipher, None, curves=supported_curves,
                server_cert_key_list=[(TEST_RSA_CERT, TEST_RSA_KEY),(TEST_ECDSA_CERT, TEST_ECDSA_KEY)],
                server_cipher_pref=server_prefs)
        result_prefix = "Certs: [RSA, ECDSA]  Client Prefs %s Server Pref: %s Vers: %-10s ... " % (cipher, server_prefs, S2N_PROTO_VERS_TO_STR[None])
        print_result(result_prefix, ret)
        if ret != 0:
            return ret

    return 0

def multiple_cert_domain_name_test(host, port):
    '''
    Test s2n server's ability to select the correct certificate based on the client ServerName extension.
    Validates that the correct certificate is selected and s_client does not throw and hostname validation errors.
    '''
    print("\n\tRunning multiple server cert domain name test:")
    for test_case in MULTI_CERT_TEST_CASES:
        cert_key_list = [(cert[0],cert[1]) for cert in test_case.server_certs]
        client_sni = test_case.client_sni
        client_ciphers = test_case.client_ciphers
        expected_cert_path = test_case.expected_cert[0]
        expect_hostname_match = test_case.expect_matching_hostname
        ret = try_handshake(host, port, client_ciphers, None, server_name=client_sni,
                expected_extensions = [TlsExtensionServerName] if expect_hostname_match == True else None,
                strict_hostname=expect_hostname_match, server_cert_key_list=cert_key_list, expected_server_cert=expected_cert_path)
        result_prefix = "\nDescription: %s\n\nclient_sni: %s\nclient_ciphers: %s\nexpected_cert: %s\nexpect_hostname_match: %s\nresult: " % (test_case.description,
                client_sni,
                client_ciphers,
                expected_cert_path,
                expect_hostname_match)
        print_result(result_prefix, ret)
        if ret != 0:
            return ret

    return 0

def main():
    parser = argparse.ArgumentParser(description='Runs TLS server integration tests against s2nd using Openssl s_client')
    parser.add_argument('host', help='The host for s2nd to bind to')
    parser.add_argument('port', type=int, help='The port for s2nd to bind to')
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

    fips_mode = False
    if environ.get("S2N_TEST_IN_FIPS_MODE") is not None:
        fips_mode = True
        print("\nRunning s2nd in FIPS mode.")

    print("\nRunning tests with: " + os.popen('openssl version').read())
    if use_corked_io == True:
        print("Corked IO is on")

    failed = 0
    failed += resume_test(host, port, test_ciphers, fips_mode, no_ticket=True)
    failed += resume_test(host, port, test_ciphers, fips_mode)
    failed += handshake_test(host, port, test_ciphers, fips_mode)
    failed += client_auth_test(host, port, test_ciphers, fips_mode)
    failed += sigalg_test(host, port, fips_mode)
    failed += sigalg_test(host, port, fips_mode, use_client_auth=True, no_ticket=True)
    failed += elliptic_curve_test(host, port, libcrypto_version, fips_mode)
    failed += elliptic_curve_fallback_test(host, port, fips_mode)
    failed += handshake_fragmentation_test(host, port, fips_mode)
    failed += ocsp_stapling_test(host, port, fips_mode)
    failed += cert_type_cipher_match_test(host, port, libcrypto_version)
    failed += multiple_cert_type_test(host, port, libcrypto_version)
    failed += multiple_cert_domain_name_test(host, port)

    return failed

if __name__ == "__main__":
    sys.exit(main())

