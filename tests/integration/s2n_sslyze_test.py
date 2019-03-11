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
import argparse
import os
import sys
import subprocess
import itertools
import multiprocessing
import json
import time
from pprint import pprint
from os import environ
from multiprocessing.pool import ThreadPool
from s2n_test_constants import *


def cleanup_processes(*processes):
    for p in processes:
        p.kill()
        p.wait()

def run_sslyze_scan(endpoint, port, scan_output_location, enter_fips_mode=False):
    """
    Run SSLyze scan against s2nd listening on `endpoint` and `port`

    :param int endpoint: endpoint for s2nd to listen on
    :param int port: port for s2nd to listen on
    :param str scan_output_location: Path and Filename of where to output JSON Results file
    :param bool enter_fips_mode: True if s2nd should enter libcrypto's FIPS mode. Libcrypto must be built with a FIPS module to enter FIPS mode.
    :return: 0 on successfully negotiation(s), -1 on failure
    """
    
    s2nd_cmd = ["../../bin/s2nd"]
    s2nd_cmd.extend([str(endpoint), str(port), "-n", "-s", "--parallelize"])
    
    s2nd_ciphers = "test_all"
    if enter_fips_mode == True:
        s2nd_ciphers = "test_all_fips"
        s2nd_cmd.append("--enter-fips-mode")
    s2nd_cmd.append("--ciphers")
    s2nd_cmd.append(s2nd_ciphers)
    
    # Run s2nd in the background
    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


    sslyze_cmd = ["sslyze"]
    sslyze_cmd.extend(["--robot", str(str(endpoint) + ":" + str(port)), str("--json_out=" + scan_output_location)])
    
    sslyze = subprocess.Popen(sslyze_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sslyze.wait(timeout=(300 * 1000))
    
    #cleanup
    cleanup_processes(s2nd, sslyze)
    
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

def check_sslyze_results(scan_output_location):
    json_obj = json.load(open(scan_output_location))
    scan_time = json_obj["total_scan_time"]
    robot_result = json_obj["accepted_targets"][0]["commands_results"]["robot"]

    if("error_message" in robot_result):
        print_result("SSLyze Error: " + robot_result["error_message"] + " ", 1)
        return 1
    
    failures = 0
    robot_attack_failure = 0
    
    if(robot_result["robot_result_enum"] != "NOT_VULNERABLE_NO_ORACLE"):
        robot_attack_failure = 1
        failures += 1
    
    print_result("ROBOT Attack Regression Test... ", robot_attack_failure)
    
    print("\nSSLyze Results Location: " + scan_output_location)
    print("SSLyze Scan Time: %0.2f seconds\n" % float(scan_time))
    
    return failures

def run_sslyze_test(host, port, fips_mode):
    seconds_since_epoch = str(int(time.time()))
    scan_output_location = "/tmp/sslyze_output_%s.json" % seconds_since_epoch
    
    run_sslyze_scan(host, port, scan_output_location, fips_mode)
    failed = check_sslyze_results(scan_output_location)
    
    os.remove(scan_output_location)
    return failed
    

def main():
    parser = argparse.ArgumentParser(description='Runs SSLyze scan against s2nd')
    parser.add_argument('host', help='The host for s2nd to bind to')
    parser.add_argument('port', type=int, help='The port for s2nd to bind to')
    parser.add_argument('--libcrypto', default='openssl-1.1.1', choices=['openssl-1.0.2', 'openssl-1.0.2-fips', 'openssl-1.1.1', 'libressl'],
            help="""The Libcrypto that s2n was built with. s2n supports different cipher suites depending on
                    libcrypto version. Defaults to openssl-1.1.1.""")
    args = parser.parse_args()

    # Retrieve the test ciphers to use based on the libcrypto version s2n was built with
    host = args.host
    port = args.port

    fips_mode = False
    if environ.get("S2N_TEST_IN_FIPS_MODE") is not None:
        fips_mode = True
        print("\n\tRunning s2nd in FIPS mode.")

    print("\n\tRunning SSLyze tests with: " + os.popen('openssl version').read())

    return run_sslyze_test(host, port, fips_mode)


if __name__ == "__main__":
    sys.exit(main())
