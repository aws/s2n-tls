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

import collections
from enum import Enum

# Number of lines of output to stdout s2nc or s2nd are expected
# to produce after a successful handshake
NUM_EXPECTED_LINES_OUTPUT = 13

class OCSP(Enum):
    ENABLED = 1
    DISABLED = 2
    MALFORMED = 3

S2N_SSLv3 = 30
S2N_TLS10 = 31
S2N_TLS11 = 32
S2N_TLS12 = 33
S2N_TLS13 = 34

ACTUAL_VERSION_STR = "Actual protocol version: {}"

# namedtuple makes iterating through ciphers across client libraries easier. The openssl_1_1_1_compatible flag is for
# s_client tests. s_client won't be able to use those ciphers.
S2N_CIPHER = collections.namedtuple('S2N_CIPHER', 'openssl_name gnutls_priority_str min_tls_vers openssl_1_1_1_compatible openssl_fips_compatible')

# Specifying a single cipher suite in GnuTLS requires specifying a "priority string" that removes all cipher suites,
# and then adds each algorithm(kx,auth,enc,mac) for a given suite. See https://www.gnutls.org/manual/html_node/Priority-Strings.html
S2N_GNUTLS_PRIORITY_PREFIX="NONE:+COMP-NULL:+CTYPE-ALL"

ALL_TEST_CIPHERS = [
    S2N_CIPHER("RC4-MD5", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+ARCFOUR-128:+MD5", S2N_SSLv3, False, False),
    S2N_CIPHER("RC4-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+ARCFOUR-128:+SHA1", S2N_SSLv3, False, False),
    S2N_CIPHER("DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+RSA:+3DES-CBC:+SHA1", S2N_SSLv3, False, True),
    S2N_CIPHER("DHE-RSA-DES-CBC3-SHA", S2N_GNUTLS_PRIORITY_PREFIX + ":+DHE-RSA:+3DES-CBC:+SHA1", S2N_SSLv3, False, False),
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

# Limit the depth of combinations with itertools permutations to reduce integration tests runtime
MAX_ITERATION_DEPTH = 3

# Expected preferences for SignatureAlgorithms in GnuTLS priority string format
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

# Test ciphers to use when s2n is built with BoringSSL. All ciphers should be avilable.
BORINGSSL_TEST_CIPHERS = ALL_TEST_CIPHERS

# Test ciphers to use when s2n is built with AWS-LC. All ciphers should be avilable.
AWSLC_TEST_CIPHERS = ALL_TEST_CIPHERS

# Test ciphers to use when s2n is built with LibreSSL. LibreSSL does not have the
# ChaCha20-Poly1305 cipher.
LIBRESSL_TEST_CIPHERS = list(filter(lambda x: "CHACHA20" not in x.openssl_name, ALL_TEST_CIPHERS))

# Dictionary to look up ciphers to use by libcrypto s2n is built with.
# Libcrypto string will be an argument to test scripts.
S2N_LIBCRYPTO_TO_TEST_CIPHERS = {
    "openssl-1.1.1"         : OPENSSL_1_1_1_TEST_CIPHERS,
    "openssl-1.0.2"         : OPENSSL_1_0_2_TEST_CIPHERS,
    "openssl-1.0.2-fips"    : OPENSSL_1_0_2_FIPS_TEST_CIPHERS,
    "libressl"              : LIBRESSL_TEST_CIPHERS,
    "boringssl"             : BORINGSSL_TEST_CIPHERS,
    "awslc"                 : AWSLC_TEST_CIPHERS,
}

S2N_LIBCRYPTO_TO_OCSP = {
    "openssl-1.1.1"         : [OCSP.ENABLED, OCSP.DISABLED, OCSP.MALFORMED],
    "openssl-1.0.2"         : [OCSP.ENABLED, OCSP.DISABLED, OCSP.MALFORMED],
    "openssl-1.0.2-fips"    : [OCSP.ENABLED, OCSP.DISABLED, OCSP.MALFORMED],
    "libressl"              : [OCSP.ENABLED, OCSP.DISABLED, OCSP.MALFORMED],
    "boringssl"             : [OCSP.DISABLED],
    "awslc"                 : [OCSP.DISABLED],
}

S2N_LIBCRYPTO_CHOICES = ['openssl-1.0.2', 'openssl-1.0.2-fips', 'openssl-1.1.1', 'libressl', 'boringssl', 'awslc']

S2N_PROTO_VERS_TO_STR = {
    S2N_SSLv3 : "SSLv3",
    S2N_TLS10 : "TLSv1.0",
    S2N_TLS11 : "TLSv1.1",
    S2N_TLS12 : "TLSv1.2",
    S2N_TLS13 : "TLSv1.3",
    None      : "Default",
}

S2N_PROTO_VERS_TO_GNUTLS = {
    S2N_SSLv3 : "VERS-SSL3.0",
    S2N_TLS10 : "VERS-TLS1.0",
    S2N_TLS11 : "VERS-TLS1.1",
    S2N_TLS12 : "VERS-TLS1.2",
    S2N_TLS13 : "VERS-TLS1.3",
}

TEST_CERT_DIRECTORY="../pems/"

TEST_RSA_CERT = TEST_CERT_DIRECTORY + "rsa_2048_sha256_wildcard_cert.pem"
TEST_RSA_KEY  = TEST_CERT_DIRECTORY + "rsa_2048_sha256_wildcard_key.pem"

TEST_ECDSA_CERT = TEST_CERT_DIRECTORY + "ecdsa_p384_pkcs1_cert.pem"
TEST_ECDSA_KEY  = TEST_CERT_DIRECTORY + "ecdsa_p384_pkcs1_key.pem"

TEST_DH_PARAMS=TEST_CERT_DIRECTORY + "dhparams_2048.pem"

# cert, key, and ocsp response for OCSP stapling tests
TEST_OCSP_CERT_DIRECTORY="../pems/ocsp/"
TEST_OCSP_CERT=TEST_OCSP_CERT_DIRECTORY + "server_cert.pem"
TEST_OCSP_KEY=TEST_OCSP_CERT_DIRECTORY + "server_key.pem"
TEST_OCSP_RESPONSE_FILE=TEST_OCSP_CERT_DIRECTORY + "ocsp_response.der"
TEST_OCSP_ECDSA_CERT=TEST_OCSP_CERT_DIRECTORY + "server_ecdsa_cert.pem"
TEST_OCSP_ECDSA_KEY=TEST_OCSP_CERT_DIRECTORY + "server_ecdsa_key.pem"
TEST_OCSP_ECDSA_RESPONSE_FILE=TEST_OCSP_CERT_DIRECTORY + "ocsp_ecdsa_response.der"

DEFAULT_CLIENT_CERT_PATH = TEST_CERT_DIRECTORY + "rsa_2048_sha256_client_cert.pem"
DEFAULT_CLIENT_KEY_PATH = TEST_CERT_DIRECTORY + "rsa_2048_sha256_client_key.pem"

TEST_SNI_CERT_DIRECTORY="../pems/sni/"
# Server certificates used to test matching domain names client with server_name
# ( cert_path, private_key_path, domains[] )
SNI_CERTS = {
    "alligator" : ( TEST_SNI_CERT_DIRECTORY + "alligator_cert.pem", TEST_SNI_CERT_DIRECTORY + "alligator_key.pem",
        ["www.alligator.com"]),
    "second_alligator_rsa" : ( TEST_SNI_CERT_DIRECTORY + "second_alligator_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY + "second_alligator_rsa_key.pem",
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
        ]),
    "narwhal_cn" : ( TEST_SNI_CERT_DIRECTORY + "narwhal_cn_cert.pem", TEST_SNI_CERT_DIRECTORY + "narwhal_cn_key.pem",
        ["www.narwhal.com"]),
    "octopus_cn_platypus_san" : ( TEST_SNI_CERT_DIRECTORY + "octopus_cn_platypus_san_cert.pem", TEST_SNI_CERT_DIRECTORY
        + "octopus_cn_platypus_san_key.pem", ["www.platypus.com"]),
    "quail_cn_rattlesnake_cn" : ( TEST_SNI_CERT_DIRECTORY + "quail_cn_rattlesnake_cn_cert.pem", TEST_SNI_CERT_DIRECTORY
        + "quail_cn_rattlesnake_cn_key.pem", ["www.quail.com", "www.rattlesnake.com"]),
    "many_animals_mixed_case" : (TEST_SNI_CERT_DIRECTORY + "many_animal_sans_mixed_case_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY + "many_animal_sans_mixed_case_rsa_key.pem",
        ["alligator.com",
         "beaver.com",
         "catFish.com",
         "WWW.dolphin.COM",
         "www.ELEPHANT.com",
         "www.Falcon.Com",
         "WWW.gorilla.COM",
         "www.horse.com",
         "WWW.IMPALA.COM",
         "WwW.jAcKaL.cOm"]),
    "embedded_wildcard" : ( TEST_SNI_CERT_DIRECTORY + "embedded_wildcard_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY
        + "embedded_wildcard_rsa_key.pem", ["www.labelstart*labelend.com"]),
    "non_empty_label_wildcard" : ( TEST_SNI_CERT_DIRECTORY + "non_empty_label_wildcard_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY
        + "non_empty_label_wildcard_rsa_key.pem", ["WILD*.middle.end"]),
    "trailing_wildcard" : ( TEST_SNI_CERT_DIRECTORY + "trailing_wildcard_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY
        + "trailing_wildcard_rsa_key.pem", ["the.prefix.*"]),
    "wildcard_insect" : ( TEST_SNI_CERT_DIRECTORY + "wildcard_insect_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY
        + "wildcard_insect_rsa_key.pem",
        ["ant.insect.hexapod",
         "BEE.insect.hexapod",
         "wasp.INSECT.hexapod",
         "butterfly.insect.hexapod",
        ]),
    "termite" : ( TEST_SNI_CERT_DIRECTORY + "termite_rsa_cert.pem", TEST_SNI_CERT_DIRECTORY + "termite_rsa_key.pem",
        [ "termite.insect.hexapod" ]),
    "underwing" : ( TEST_SNI_CERT_DIRECTORY + "underwing_ecdsa_cert.pem", TEST_SNI_CERT_DIRECTORY + "underwing_ecdsa_key.pem",
        [ "underwing.insect.hexapod" ])
}

# Test cases for certificate selection.
# Test inputs: server certificates to load into s2nd, client SNI and capabilities, outputs are selected server cert
# and negotiated cipher.
MultiCertTest = collections.namedtuple('MultiCertTest', 'description server_certs client_sni client_ciphers expected_cert expect_matching_hostname')
MULTI_CERT_TEST_CASES= [
    MultiCertTest(
        description="Test basic SNI match for default cert.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test basic SNI matches for non-default cert.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.beaver.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["beaver"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test default cert is selected when there are no SNI matches.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="not.a.match",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test default cert is selected when no SNI is sent.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni=None,
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test ECDSA cert is selected with matching domain and client only supports ECDSA.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers="ECDHE-ECDSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test ECDSA cert selected when: domain matches for both ECDSA+RSA, client supports ECDSA+RSA "\
                    " ciphers, ECDSA is higher priority on server side.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers="ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test domain match is highest priority. Domain matching ECDSA certificate should be selected"\
                    " even if domain mismatched RSA certificate is available and RSA cipher is higher priority.",
        server_certs=[SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers="ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA256",
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test certificate with single SAN entry matching is selected before mismatched multi SAN cert",
        server_certs=[SNI_CERTS["many_animals"] , SNI_CERTS["alligator"]],
        client_sni="www.alligator.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
        # many_animals was the first cert added
    MultiCertTest(
        description="Test default cert with multiple sans and no SNI sent.",
        server_certs=[SNI_CERTS["many_animals"] , SNI_CERTS["alligator"]],
        client_sni=None,
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["many_animals"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test certificate match with CN",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["narwhal_cn"] ],
        client_sni="www.narwhal.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["narwhal_cn"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test SAN+CN cert can match using SAN.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["octopus_cn_platypus_san"] ],
        client_sni="www.platypus.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["octopus_cn_platypus_san"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test that CN is not considered for matching if the certificate contains SANs.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["octopus_cn_platypus_san"] ],
        client_sni="www.octopus.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test certificate with multiple CNs can match.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["quail_cn_rattlesnake_cn"] ],
        client_sni="www.rattlesnake.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["quail_cn_rattlesnake_cn"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test cert with embedded wildcard is not treated as a wildcard.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["embedded_wildcard"] ],
        client_sni="www.labelstartWILDCARDlabelend.com",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test non empty left label wildcard cert is not treated as a wildcard."\
                    " s2n only supports wildcards with a single * as the left label",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["non_empty_label_wildcard"] ],
        client_sni="WILDCARD.middle.end",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test cert with trailing * is not treated as wildcard.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["trailing_wildcard"] ],
        client_sni="the.prefix.WILDCARD",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Certificate with exact sni match(termite.insect.hexapod) is preferred over wildcard"\
                    " *.insect.hexapod",
        server_certs=[ SNI_CERTS["wildcard_insect"], SNI_CERTS["alligator"], SNI_CERTS["termite"] ],
        client_sni="termite.insect.hexapod",
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["termite"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="ECDSA Certificate with exact sni match(underwing.insect.hexapod) is preferred over RSA wildcard"\
                    " *.insect.hexapod when RSA ciphers are higher priority than ECDSA in sever preferences.",
        server_certs=[ SNI_CERTS["wildcard_insect"], SNI_CERTS["alligator"], SNI_CERTS["underwing"] ],
        client_sni="underwing.insect.hexapod",
        # AES128-GCM-SHA256 is prioritized about ECDHE-ECDSA-AES128-SHA in
        # the "test_all" server cipher preferences
        client_ciphers="AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA",
        expected_cert=SNI_CERTS["underwing"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Firstly loaded matching certificate should be selected among certificates with the same domain names",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["second_alligator_rsa"] ],
        client_sni="www.alligator.com",
        client_ciphers="AES128-GCM-SHA256",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Firstly loaded matching certificate should be selected among matching+non-matching certificates",
        server_certs=[ SNI_CERTS["beaver"], SNI_CERTS["alligator"], SNI_CERTS["second_alligator_rsa"] ],
        client_sni="www.alligator.com",
        client_ciphers="AES128-GCM-SHA256",
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True)]
# Positive test for wildcard matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
        description="Test wildcard *.insect.hexapod matches subdomain " + specific_insect_domain,
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["wildcard_insect"] ],
        client_sni=specific_insect_domain,
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["wildcard_insect"],
        expect_matching_hostname=True) for specific_insect_domain in SNI_CERTS["wildcard_insect"][2]])
# Positive test for basic SAN matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
        description="Match SAN " + many_animal_domain + " in many_animals cert",
        server_certs= [ SNI_CERTS["alligator"], SNI_CERTS["many_animals"] ],
        client_sni=many_animal_domain,
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["many_animals"],
        expect_matching_hostname=True) for many_animal_domain in SNI_CERTS["many_animals"][2]])
# Positive test for mixed cased SAN matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
        description="Match SAN " + many_animal_domain + " in many_animals_mixed_case cert",
        server_certs= [SNI_CERTS["alligator"] , SNI_CERTS["many_animals_mixed_case"]],
        client_sni=many_animal_domain,
        client_ciphers="ECDHE-RSA-AES128-SHA",
        expected_cert=SNI_CERTS["many_animals_mixed_case"],
        expect_matching_hostname=True) for many_animal_domain in SNI_CERTS["many_animals_mixed_case"][2]])
