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

import sys
import ssl
import socket

# All supported ciphers
S2N_CIPHERS=[
    "RC4-MD5",
    "RC4-SHA",
    "DES-CBC3-SHA",
    "EDH-RSA-DES-CBC3-SHA",
    "AES128-SHA",
    "DHE-RSA-AES128-SHA",
    "AES256-SHA",
    "DHE-RSA-AES256-SHA",
    "AES128-SHA256",
    "AES256-SHA256",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA256",
    "AES128-GCM-SHA256",
    "DHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-DES-CBC3-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "AES256-GCM-SHA384",
]

def try_handshake(endpoint, port, cipher):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers=cipher)
    except ssl.SSLError as err:
        print str(err)
        return -1
    try:
        ssl_sock.connect((endpoint, port))
    except Exception as err:
        print str(err)
        return -1
    
    ssl_sock.send(cipher)
    return 0

def main(argv):
    if len(argv) < 2:
        print "s2n_handshake_test.py host port"
        sys.exit(1)

    print "Running handshake tests with " + str(ssl.OPENSSL_VERSION)
    failed = 0
    for cipher in S2N_CIPHERS:
        ret = try_handshake(argv[0], int(argv[1]), cipher)
        if ret == 0:
            print cipher + "...SUCCEEDED"
        else:
            print cipher + "...FAILED"
            failed = 1
    return failed

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
