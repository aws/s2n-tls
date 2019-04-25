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

# namedtuple makes iterating through ciphers across client libraries easier. The openssl_1_1_1_compatible flag is for
# s_client tests. s_client won't be able to use those ciphers.
S2N_CIPHER = collections.namedtuple('S2N_CIPHER', 'openssl_name gnutls_priority_str min_tls_vers openssl_1_1_1_compatible openssl_fips_compatible')

# Specifying a single cipher suite in GnuTLS requires specifying a "priority string" that removes all cipher suites,
# and then adds each algorithm(kx,auth,enc,mac) for a given suite. See https://www.gnutls.org/manual/html_node/Priority-Strings.html
S2N_GNUTLS_PRIORITY_PREFIX="NONE:+COMP-NULL:+CTYPE-ALL:+CURVE-ALL"

ALL_TEST_CIPHERS = [
    S2N_CIPHER("RC4-MD5", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+ARCFOUR-128:+MD5", S2N_SSLv3, False, False),
    S2N_CIPHER("RC4-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+ARCFOUR-128:+SHA1", S2N_SSLv3, False, False),
    S2N_CIPHER("DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+3DES-CBC:+SHA1", S2N_SSLv3, False, True),
    S2N_CIPHER("EDH-RSA-DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+3DES-CBC:+SHA1", S2N_SSLv3, False, False),
    S2N_CIPHER("AES128-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-128-CBC:+SHA1", S2N_SSLv3, True, True),
    S2N_CIPHER("DHE-RSA-AES128-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-128-CBC:+SHA1", S2N_SSLv3, True, False),
    S2N_CIPHER("AES256-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-256-CBC:+SHA1", S2N_SSLv3, True, True),
    S2N_CIPHER("DHE-RSA-AES256-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-256-CBC:+SHA1", S2N_SSLv3, True, False),
    S2N_CIPHER("AES128-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-128-CBC:+SHA256", S2N_TLS12, True, True),
    S2N_CIPHER("AES256-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-256-CBC:+SHA256", S2N_TLS12, True, True),
    S2N_CIPHER("DHE-RSA-AES128-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-128-CBC:+SHA256", S2N_TLS12, True, True),
    S2N_CIPHER("DHE-RSA-AES256-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-256-CBC:+SHA256", S2N_TLS12, True, True),
    S2N_CIPHER("AES128-GCM-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-128-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("AES256-GCM-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+AES-256-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("DHE-RSA-AES128-GCM-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-128-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("DHE-RSA-AES256-GCM-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+AES-256-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-ECDSA-AES128-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-ECDSA:+AES-128-CBC:+SHA1", S2N_SSLv3, True, False),
    S2N_CIPHER("ECDHE-ECDSA-AES256-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-ECDSA:+AES-256-CBC:+SHA1", S2N_SSLv3, True, False),
    S2N_CIPHER("ECDHE-ECDSA-AES128-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-ECDSA:+AES-128-CBC:+SHA256", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-ECDSA-AES256-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-ECDSA:+AES-256-CBC:+SHA384", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-ECDSA-AES128-GCM-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-ECDSA:+AES-128-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-ECDSA-AES256-GCM-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-ECDSA:+AES-256-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-RSA-DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+3DES-CBC:+SHA1", S2N_SSLv3, False, False),
    S2N_CIPHER("ECDHE-RSA-AES128-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-128-CBC:+SHA1", S2N_SSLv3, True, False),
    S2N_CIPHER("ECDHE-RSA-AES256-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-256-CBC:+SHA1", S2N_SSLv3, True, False),
    S2N_CIPHER("ECDHE-RSA-RC4-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+ARCFOUR-128:+SHA1", S2N_SSLv3, False, False),
    S2N_CIPHER("ECDHE-RSA-AES128-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-128-CBC:+SHA256", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-RSA-AES256-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-256-CBC:+SHA384", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-RSA-AES128-GCM-SHA256", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-128-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-RSA-AES256-GCM-SHA384", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+AES-256-GCM:+AEAD", S2N_TLS12, True, True),
    S2N_CIPHER("ECDHE-RSA-CHACHA20-POLY1305", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-RSA:+CHACHA20-POLY1305:+AEAD", S2N_TLS12, True, False),
    S2N_CIPHER("ECDHE-ECDSA-CHACHA20-POLY1305", S2N_GNUTLS_PRIORITY_PREFIX + ":+ECDHE-ECDSA:+CHACHA20-POLY1305:+AEAD", S2N_TLS12, True, False),
    S2N_CIPHER("DHE-RSA-CHACHA20-POLY1305", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+CHACHA20-POLY1305:+AEAD", S2N_TLS12, True, False),
]

# Expected preferences for SignatureAlgorithms in GnuTLS priority string format
# See https://github.com/awslabs/s2n/blob/master/tls/s2n_tls_digest_preferences.h
EXPECTED_RSA_SIGNATURE_ALGORITHM_PREFS = [
    "SIGN-RSA-SHA256",
    "SIGN-RSA-SHA384",
    "SIGN-RSA-SHA512",
    "SIGN-RSA-SHA224",
    "SIGN-RSA-SHA1",
]

EXPECTED_ECDSA_SIGNATURE_ALGORITHM_PREFS = [
    "SIGN-ECDSA-SHA256",
    "SIGN-ECDSA-SHA384",
    "SIGN-ECDSA-SHA512",
    "SIGN-ECDSA-SHA224",
    "SIGN-ECDSA-SHA1",
]

# Test ciphers to use when s2n built with Openssl 1.1.1 libcrypto. All ciphers should be available.
OPENSSL_1_1_1_TEST_CIPHERS = ALL_TEST_CIPHERS

# Test ciphers to use when s2n is built with Openssl 1.0.2 libcrypto. 1.0.2 does not have the
# ChaCha20-Poly1305 cipher.
OPENSSL_1_0_2_TEST_CIPHERS = list(filter(lambda x: "CHACHA20" not in x.openssl_name, ALL_TEST_CIPHERS))

# Test ciphers to use when s2n is built with Openssl 1.0.2 libcrypto that is linked with a FIPS module.
OPENSSL_1_0_2_FIPS_TEST_CIPHERS = list(filter(lambda x: x.openssl_fips_compatible == True, ALL_TEST_CIPHERS))

# Test ciphers to use when s2n is built with LibreSSL libcrypto. s2n does not implement the
# ChaCha20-Poly1305 cipher offered by LibreSSL.
LIBRESSL_TEST_CIPHERS = list(filter(lambda x: "CHACHA20" not in x.openssl_name, ALL_TEST_CIPHERS))

# Dictionary to look up ciphers to use by libcrypto s2n is built with.
# Libcrypto string will be an argument to test scripts.
S2N_LIBCRYPTO_TO_TEST_CIPHERS = {
    "openssl-1.1.1"         : OPENSSL_1_1_1_TEST_CIPHERS,
    "openssl-1.0.2"         : OPENSSL_1_0_2_TEST_CIPHERS,
    "openssl-1.0.2-fips"    : OPENSSL_1_0_2_FIPS_TEST_CIPHERS,
    "libressl"              : LIBRESSL_TEST_CIPHERS,
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

TEST_CERT_DIRECTORY="../pems/"

TEST_RSA_CERT=TEST_CERT_DIRECTORY + "rsa_2048_sha256_wildcard_cert.pem"
TEST_RSA_KEY=TEST_CERT_DIRECTORY + "rsa_2048_sha256_wildcard_key.pem"

TEST_ECDSA_CERT=TEST_CERT_DIRECTORY + "ecdsa_p384_pkcs1_cert.pem"
TEST_ECDSA_KEY=TEST_CERT_DIRECTORY + "ecdsa_p384_pkcs1_key.pem"

TEST_DH_PARAMS=TEST_CERT_DIRECTORY + "dhparams_2048.pem"

# cert, key, and ocsp response for OCSP stapling tests
TEST_OCSP_CERT_DIRECTORY="../pems/ocsp/"
TEST_OCSP_CERT=TEST_OCSP_CERT_DIRECTORY + "server_cert.pem"
TEST_OCSP_KEY=TEST_OCSP_CERT_DIRECTORY + "server_key.pem"
TEST_OCSP_RESPONSE_FILE=TEST_OCSP_CERT_DIRECTORY + "ocsp_response.der"

DEFAULT_CLIENT_CERT_PATH = TEST_CERT_DIRECTORY + "rsa_2048_sha256_client_cert.pem"
DEFAULT_CLIENT_KEY_PATH = TEST_CERT_DIRECTORY + "rsa_2048_sha256_client_key.pem"

TEST_SNI_CERT_DIRECTORY="../pems/sni/"
# Server certificates used to test matching domain names client with server_name
# ( cert_path, private_key_path, domains[] )
SNI_CERTS = {
    "alligator" : ( TEST_SNI_CERT_DIRECTORY + "alligator_cert.pem", TEST_SNI_CERT_DIRECTORY + "alligator_key.pem",
        ["www.alligator.com"]),
    "alligator_ecdsa" : ( TEST_SNI_CERT_DIRECTORY + "alligator_ecdsa_cert.pem", TEST_SNI_CERT_DIRECTORY +
        "alligator_ecdsa_key.pem", ["www.alligator.com"]),
    "beaver"    : ( TEST_SNI_CERT_DIRECTORY + "beaver_cert.pem", TEST_SNI_CERT_DIRECTORY + "beaver_key.pem",
        ["www.beaver.com"]),
    "many_animals" : (TEST_SNI_CERT_DIRECTORY + "many_animal_sans_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY + "many_animal_sans_rsa_key.pem",
        ["www.catfish.com",
         "www.dolphin.com",
         "www.elephant.com",
         "www.falcon.com",
         "www.gorilla.com",
         "www.horse.com",
         "www.impala.com",
         # "Simple hostname"
         "Jackal",
         "k.e.e.l.b.i.l.l.e.d.t.o.u.c.a.n",
         # SAN on this cert is actually "ladybug.ladybug"
         # Verify case insensitivity works as expected.
         "LADYBUG.LADYBUG",
         "com.penguin.macaroni"
        ])
}

# Test cases with certificates to load into s2nd and expected behavior
# ( certificates_to_use[], (domain_name, expected_certificate, expected_domain_match, client_cipher)[]  )
SNI_CERT_TEST_CASES = [
    ([SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        [("www.alligator.com", SNI_CERTS["alligator"], True, "ECDHE-RSA-AES128-SHA"),
        ("www.beaver.com", SNI_CERTS["beaver"], True,  "ECDHE-RSA-AES128-SHA"),
        # This is a mismatch, expect the first cert added is selected.
        ("not.a.match", SNI_CERTS["alligator"], False, "ECDHE-RSA-AES128-SHA"),
        # No SNI sent at all. expect the first cert added is selected.
        (None, SNI_CERTS["alligator"], False, "ECDHE-RSA-AES128-SHA"),
        # We have two certificates that match www.alligator.com but the client
        # only supports ECDSA. The ECDSA cert should be served
        ("www.alligator.com", SNI_CERTS["alligator_ecdsa"], True, "ECDHE-ECDSA-AES128-SHA"),
        # Client supports mixed auth types, expect we negotiate the higher priority cipher
        # and select the correct cert
        ("www.alligator.com", SNI_CERTS["alligator_ecdsa"], True, "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA")]),
    ([ SNI_CERTS["many_animals"] , SNI_CERTS["alligator"] ],
        # Every valid many animal_domain should work
        [(many_animal_domain, SNI_CERTS["many_animals"], True, "ECDHE-RSA-AES128-SHA") for many_animal_domain in SNI_CERTS["many_animals"][2]] +
        # Make sure alligator is still served properly
        [("www.alligator.com", SNI_CERTS["alligator"], True, "ECDHE-RSA-AES128-SHA"),
        # many_animals was the first cert added
        (None, SNI_CERTS["many_animals"], False, "ECDHE-RSA-AES128-SHA")]),
    ([SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        # Assumptions in this test:
        #   - beaver is the default cert and is rsa
        #   - There is an SNI mismatch for beaver
        #   - There is an SNI match for alligator_ecdsa but only for ECDSA ciphers
        #   - Server prefers ECDHE-RSA-AES128-SHA above ECDHE-ECDSA-AES128-SHA256
        # Expectation:
        #   - Server selected alligator_ecdsa cert since SNI match is a higher "priority" than cipher preference.
        [("www.alligator.com", SNI_CERTS["alligator_ecdsa"], True, "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA256")])
]
