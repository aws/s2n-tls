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

import collections

S2N_SSLv3 = 30
S2N_TLS10 = 31
S2N_TLS11 = 32
S2N_TLS12 = 33

# namedtuple makes iterating through ciphers across client libraries easier. The openssl_1_1_0_compatible flag is for
# s_client tests. s_client won't be able to use those ciphers.
S2N_CIPHER = collections.namedtuple('S2N_CIPHER', 'openssl_name gnutls_priority_str min_tls_vers openssl_1_1_0_compatible')

# Specifying a single cipher suite in GnuTLS requires specifying a "priority string" that removes all cipher suites,
# and then adds each algorithm(kx,auth,enc,mac) for a given suite. See https://www.gnutls.org/manual/html_node/Priority-Strings.html
S2N_GNUTLS_PRIORITY_PREFIX="NONE:+COMP-NULL:+CTYPE-ALL:+CURVE-ALL"

ALL_TEST_CIPHERS = [
    S2N_CIPHER("RC4-MD5", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+ARCFOUR-128:+MD5", S2N_SSLv3, False),
    S2N_CIPHER("RC4-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+ARCFOUR-128:+SHA1", S2N_SSLv3, False),
    S2N_CIPHER("DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+3DES-CBC:+SHA1", S2N_SSLv3, False),
    S2N_CIPHER("EDH-RSA-DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+3DES-CBC:+SHA1", S2N_SSLv3, False),
    S2N_CIPHER("AES128-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-128-CBC:+SHA1", S2N_TLS10, True),
    S2N_CIPHER("DHE-RSA-AES128-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-128-CBC:+SHA1", S2N_TLS10, True),
    S2N_CIPHER("AES256-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-256-CBC:+SHA1", S2N_TLS10, True),
    S2N_CIPHER("DHE-RSA-AES256-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-256-CBC:+SHA1", S2N_TLS10, True),
    S2N_CIPHER("AES128-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-128-CBC:+SHA256", S2N_TLS12, True),
    S2N_CIPHER("AES256-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-256-CBC:+SHA256", S2N_TLS12, True),
    S2N_CIPHER("DHE-RSA-AES128-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-128-CBC:+SHA256", S2N_TLS12, True),
    S2N_CIPHER("DHE-RSA-AES256-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-256-CBC:+SHA256", S2N_TLS12, True),
    S2N_CIPHER("AES128-GCM-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-128-GCM:+AEAD", S2N_TLS12, True),
    S2N_CIPHER("AES256-GCM-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-256-GCM:+AEAD", S2N_TLS12, True),
    S2N_CIPHER("DHE-RSA-AES128-GCM-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-128-GCM:+AEAD", S2N_TLS12, True),
    S2N_CIPHER("DHE-RSA-AES256-GCM-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-256-GCM:+AEAD", S2N_TLS12, True),
    S2N_CIPHER("ECDHE-RSA-DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+3DES-CBC:+SHA1", S2N_TLS10, False),
    S2N_CIPHER("ECDHE-RSA-AES128-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-128-CBC:+SHA1", S2N_TLS10, True),
    S2N_CIPHER("ECDHE-RSA-AES256-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-256-CBC:+SHA1", S2N_TLS10, True),
    S2N_CIPHER("ECDHE-RSA-AES128-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-128-CBC:+SHA256", S2N_TLS12, True),
    S2N_CIPHER("ECDHE-RSA-AES256-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-256-CBC:+SHA384", S2N_TLS12, True),
    S2N_CIPHER("ECDHE-RSA-AES128-GCM-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-128-GCM:+AEAD", S2N_TLS12, True),
    S2N_CIPHER("ECDHE-RSA-AES256-GCM-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-256-GCM:+AEAD", S2N_TLS12, True),
    S2N_CIPHER("ECDHE-RSA-CHACHA20-POLY1305", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+CHACHA20-POLY1305:+AEAD", S2N_TLS12, True),
    S2N_CIPHER("DHE-RSA-CHACHA20-POLY1305", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+CHACHA20-POLY1305:+AEAD", S2N_TLS12, True),
]

# Test ciphers to use when s2n built with Openssl 1.1.0 libcrypto. All ciphers should be available.
OPENSSL_1_1_0_TEST_CIPHERS = ALL_TEST_CIPHERS

# Test ciphers to use when s2n is built with Openssl 1.0.2 libcrypto. 1.0.2 does not have the
# ChaCha20-Poly1305 cipher.
OPENSSL_1_0_2_TEST_CIPHERS = list(filter(lambda x: x.openssl_name != "ECDHE-RSA-CHACHA20-POLY1305" and x.openssl_name != "DHE-RSA-CHACHA20-POLY1305", ALL_TEST_CIPHERS))

# Test ciphers to use when s2n is built with LibreSSL libcrypto. s2n does not implement the
# ChaCha20-Poly1305 cipher offered by LibreSSL.
LIBRESSL_TEST_CIPHERS = list(filter(lambda x: x.openssl_name != "ECDHE-RSA-CHACHA20-POLY1305" and x.openssl_name != "DHE-RSA-CHACHA20-POLY1305", ALL_TEST_CIPHERS))

# Dictionary to look up ciphers to use by libcrypto s2n is built with.
# Libcrypto string will be an argument to test scripts.
S2N_LIBCRYPTO_TO_TEST_CIPHERS = {
    "openssl-1.1.0" : OPENSSL_1_1_0_TEST_CIPHERS,
    "openssl-1.0.2" : OPENSSL_1_0_2_TEST_CIPHERS,
    "libressl"      : LIBRESSL_TEST_CIPHERS,
}

S2N_PROTO_VERS_TO_STR = {
    S2N_SSLv3 : "SSLv3",
    S2N_TLS10 : "TLSv1.0",
    S2N_TLS11 : "TLSv1.1",
    S2N_TLS12 : "TLSv1.2",
}

S2N_PROTO_VERS_TO_GNUTLS = {
    S2N_SSLv3 : "VERS-SSL3.0",
    S2N_TLS10 : "VERS-TLS1.0",
    S2N_TLS11 : "VERS-TLS1.1",
    S2N_TLS12 : "VERS-TLS1.2",
}

