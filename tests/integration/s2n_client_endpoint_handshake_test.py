#
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import os
import sys
import time
import socket
import subprocess
import itertools
from s2n_test_constants import *

well_known_endpoints = [
    "amazon.com",
    "facebook.com",
    "google.com",
    "netflix.com",
    "s3.amazonaws.com",
    "twitter.com",
    "wikipedia.org",
    "yahoo.com",
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

def try_client_handshake(endpoint):
    s2nc_cmd = ["../../bin/s2nc", "-f",  "./trust-store/ca-bundle.crt", "-a", "http/1.1", str(endpoint)]

    # Add S2N_ENABLE_CLIENT_MODE to env variables
    envVars = os.environ.copy()
    envVars["S2N_ENABLE_CLIENT_MODE"] = "1"
    currentDir = os.path.dirname(os.path.realpath(__file__))
    s2nc = subprocess.Popen(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=envVars, cwd=currentDir)

    found = 0
    for line in range(0, 10):
        output = s2nc.stdout.readline().decode("utf-8")
        if "Cipher negotiated" in str(output):
            found = 1
            break

    s2nc.kill()
    s2nc.wait()

    if found == 0:
        return -1

    return 0

def well_known_endpoints_test():

    print("\n\tTesting s2n Client with Well Known Endpoints:")

    maxRetries = 5;
    failed = 0
    for endpoint in well_known_endpoints:
        # Retry handshake in case there are any problems going over the internet
        for i in range(1, maxRetries):
            ret = try_client_handshake(endpoint)
            if ret is 0:
                break
            else:
                time.sleep(i)
        
        print_result("Endpoint:  %-40s... " % endpoint, ret)
        if ret != 0:
            failed += 1

    return failed

def main(argv):
    if len(argv) < 2:
        print("s2n_handshake_test_s_client.py host port")
        sys.exit(1)

    host = argv[0]
    port = argv[1]

    failed = 0
    failed += well_known_endpoints_test()
    return failed

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

