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
Dynamic record size tests using s2nc against Openssl s_server
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

test_file = './data/test_buf'
file_size = os.path.getsize(test_file)

def cleanup_processes(*processes):
    for p in processes:
        p.kill()
        p.wait()


def try_dynamic_record(endpoint, port, cipher, ssl_version, threshold, server_cert=None, server_key=None, sig_algs=None, curves=None, dh_params=None):
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
    s_server_cmd = ["openssl", "s_server", PROTO_VERS_TO_S_SERVER_ARG[ssl_version],
            "-accept", str(port)]
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
        server_error = s_server.stderr.read().decode("utf-8")
        if "no cipher match" in server_error:
            # print ("Skipped unsupported cipher: {}".format(cipher))
            return -2

        sys.stderr.write("Failed to start s_server: {}\nSTDERR: {}\n".format(" ".join(s_server_cmd), server_error))
        cleanup_processes(s_server)
        return -1

    # Fire up s2nc
    # print("\n\tRunning s2n dynamic record size tests with threshold:", threshold)
    s2nc_cmd = ["../../bin/s2nc", "-e", "-D", str(threshold), "-t", "1", "-c", "test_all", "-i"]
    s2nc_cmd.extend([str(endpoint), str(port)])

    file_input = open(test_file)
    s2nc = subprocess.Popen(s2nc_cmd, stdin=file_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait file send complete
    s2nc.wait()
    cleanup_processes(s_server)

    # Read from s2nc until we get successful connection message
    found = 0
    seperators = 0
    for line in range(0, 10):
        output = s2nc.stdout.readline().decode("utf-8")
        if output.strip() == "Connected to {}:{}".format(endpoint, port):
            found = 1

    if not found:
        sys.stderr.write("= TEST FAILED =\ns_server cmd: {}\n s_server STDERR: {}\n\ns2nc cmd: {}\nSTDERR {}\n".format(" ".join(s_server_cmd), s_server.stderr.read().decode("utf-8"), " ".join(s2nc_cmd), s2nc.stderr.read().decode("utf-8")))
        return -1   

    return 0

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

def run_test(host, port, ssl_version, cipher, threshold):
    cipher_name = cipher.openssl_name

    failed = 0
    tcpdump_filter = "dst port " + str(port)
    tcpdump_cmd = ["sudo", "tcpdump", "-i", "lo", "-n", "-B", "65535", tcpdump_filter]
    tcpdump = subprocess.Popen(tcpdump_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    ret = try_dynamic_record(host, port, cipher_name, ssl_version, threshold)
    # wait for pipe ready
    sleep(2)
    subprocess.call(["sudo", "killall", "-9", "tcpdump"])
    out = tcpdump.communicate()[0].decode("utf-8")
    if out == '':
        print ("No output from PIPE, skip")
        return 0
    out_array = out.split('\n')
    # Skip no cipher match error
    if ret != -2:
        failed += ret
    if 0 == ret:
        # print("\nAnalyzing tcpdump results for cipher {}".format(cipher_name))
        # Case 1: first half of application data is optimized for latency
        failed += analyze_latency_dump(out_array)
        # Case 2: second half of application data is optimize for throughput
        failed += analyze_throughput_dump(out_array)
        result_prefix = "Cipher: %-28s Vers: %-8s ... " % (cipher_name, S2N_PROTO_VERS_TO_STR[ssl_version])
        print_result(result_prefix, failed)

    return failed


def test(host, port, test_ciphers, threshold):
    failed = 0
    ssl_version = S2N_TLS12

    for cipher in test_ciphers:
        cipher_vers = cipher.min_tls_vers
        if not cipher.openssl_1_1_1_compatible:
            continue
        if ssl_version < cipher_vers:
            continue
        result = run_test(host, port, ssl_version, cipher, threshold)
        if result != 0:
            failed += 1
            break

    return failed

def analyze_latency_dump(array):
    failed = 0
    mss = get_local_mtu() - 40
    first_line = array[0]
    if ("mss" in first_line):
        mss_pos = first_line.find("mss")
        mss_str = first_line[mss_pos : mss_pos + 10]
        mss = int(mss_str[4 : mss_str.find(',')])
    else:
        print ("use default mss")
    # print("mss={}".format(mss))
    
    for i in range(0, 18):
        output = array[i]
        # print(output)
        pos = output.find("length")
        if pos < 0:
            continue
        length = output[pos + 6 : len(output)]
        # Tcp package size should always <= mss
        if int(length) > mss:
            failed = 1
            break

    return failed

def analyze_throughput_dump(array):
    failed = 1
    array_len = len(array)

    for i in range(18, 36):
        if i >= array_len:
            print("Array len is ", array_len, ", expecting >= ", i)
            print(array)
            return failed
        output = array[i]
        # print(output)
        pos = output.find("length")
        if pos < 0:
            continue
        length = output[pos + 6 : len(output)]
        # Tcp package size can exceed MTU, which results in segementation
        if int(length) > 1500:
            failed = 0
            break

    return failed

def get_local_mtu():
    cmd = ["ifconfig", "lo"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    mtu = 65536
    for line in range(0, 5):
        output = p.stdout.readline().decode("utf-8")
        if ("MTU:" in output):
            word_list = output.split()
            mtu_list = word_list[3].split(':')
            mtu = mtu_list[1]
            break

    p.wait()
    return int(mtu)


def main():
    parser = argparse.ArgumentParser(description='Runs TLS server integration tests against Openssl s_server using s2nc')
    parser.add_argument('host', help='The host for s2nc to connect to')
    parser.add_argument('port', type=int, help='The port for s_server to bind to')
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=S2N_LIBCRYPTO_CHOICES,
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
    args = parser.parse_args()

    # Retrieve the test ciphers to use based on the libcrypto version s2n was built with
    test_ciphers = S2N_LIBCRYPTO_TO_TEST_CIPHERS[args.libcrypto]    
    host = args.host
    port = args.port

    local_mtu = get_local_mtu()
    # Simulate common MTU 1500
    subprocess.call(["sudo", "ifconfig", "lo", "mtu", "1500"])    
    
    failed = 0
    print("\n\tRunning s2n dynamic record size tests\n\t")
    failed += test(host, port, test_ciphers, int(file_size / 2))

    # Recover localhost MTU
    subprocess.call(["sudo", "ifconfig", "lo", "mtu", str(local_mtu)])

    # print_result("TLS dynamic record size test " , failed)

    return failed


if __name__ == "__main__":
    sys.exit(main())

