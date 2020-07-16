import collections

from common import Certificates, Ciphers, Curves, Protocols, AvailablePorts
from constants import TEST_SNI_CERT_DIRECTORY
from providers import S2N, OpenSSL, BoringSSL


# The boolean configuration will let a test run for True and False
# for some value. For example, using the insecure flag.
BOOLEAN = [True, False]


# List of all protocols to be tested
PROTOCOLS = [
    Protocols.TLS13,
    Protocols.TLS12,
    Protocols.TLS11,
    Protocols.TLS10,
]


# List of providers that will be tested.
PROVIDERS = [S2N, OpenSSL]


# List of binary TLS13 settings
TLS13 = [True, False]


# List of all curves that will be tested.
ALL_TEST_CURVES = [
    Curves.X25519,
    Curves.P256,
    Curves.P384,
]


# List of all certificates that will be tested.
ALL_TEST_CERTS = [
    Certificates.RSA_1024_SHA256,
    Certificates.RSA_1024_SHA384,
    Certificates.RSA_1024_SHA512,
    Certificates.RSA_2048_SHA256,
    Certificates.RSA_2048_SHA384,
    Certificates.RSA_2048_SHA512,
    Certificates.RSA_3072_SHA256,
    Certificates.RSA_3072_SHA384,
    Certificates.RSA_3072_SHA512,
    Certificates.RSA_4096_SHA256,
    Certificates.RSA_4096_SHA384,
    Certificates.RSA_4096_SHA512,
    Certificates.ECDSA_256,
    Certificates.ECDSA_384,
    Certificates.RSA_PSS_2048_SHA256,
]


# List of all ciphers that will be tested.
ALL_TEST_CIPHERS = [
    Ciphers.DHE_RSA_AES128_SHA,
    Ciphers.DHE_RSA_AES256_SHA,
    Ciphers.DHE_RSA_AES128_SHA256,
    Ciphers.DHE_RSA_AES256_SHA256,
    Ciphers.DHE_RSA_AES128_GCM_SHA256,
    Ciphers.DHE_RSA_AES256_GCM_SHA384,
    Ciphers.DHE_RSA_CHACHA20_POLY1305,

    Ciphers.AES128_SHA,
    Ciphers.AES256_SHA,
    Ciphers.AES128_SHA256,
    Ciphers.AES256_SHA256,
    Ciphers.AES128_GCM_SHA256,
    Ciphers.AES256_GCM_SHA384,

    Ciphers.ECDHE_ECDSA_AES128_GCM_SHA256,
    Ciphers.ECDHE_ECDSA_AES256_GCM_SHA384,
    Ciphers.ECDHE_ECDSA_AES128_SHA256,
    Ciphers.ECDHE_ECDSA_AES256_SHA384,
    Ciphers.ECDHE_ECDSA_AES128_SHA,
    Ciphers.ECDHE_ECDSA_AES256_SHA,
    Ciphers.ECDHE_ECDSA_CHACHA20_POLY1305,

    Ciphers.ECDHE_RSA_AES128_SHA,
    Ciphers.ECDHE_RSA_AES256_SHA,
    Ciphers.ECDHE_RSA_AES128_SHA256,
    Ciphers.ECDHE_RSA_AES256_SHA384,
    Ciphers.ECDHE_RSA_AES128_GCM_SHA256,
    Ciphers.ECDHE_RSA_AES256_GCM_SHA384,
    Ciphers.ECDHE_RSA_CHACHA20_POLY1305,

    Ciphers.CHACHA20_POLY1305_SHA256,
]

# List of TLS13 Ciphers
TLS13_CIPHERS = [
    Ciphers.CHACHA20_POLY1305_SHA256,
    Ciphers.AES128_GCM_SHA256,
    Ciphers.AES256_GCM_SHA384,
]

# List of providers that will be tested.
PROVIDERS = [S2N, OpenSSL]


# List of ports available to tests.
available_ports = AvailablePorts()


# Server certificates used to test matching domain names client with server_name
# ( cert_path, private_key_path, domains[] )
SNI_CERTS = {
    "alligator" : (
        TEST_SNI_CERT_DIRECTORY + "alligator_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "alligator_key.pem",
        ["www.alligator.com"]
    ),
    "second_alligator_rsa" : (
        TEST_SNI_CERT_DIRECTORY + "second_alligator_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "second_alligator_rsa_key.pem",
        ["www.alligator.com"]
    ),
    "alligator_ecdsa" : (
        TEST_SNI_CERT_DIRECTORY + "alligator_ecdsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "alligator_ecdsa_key.pem",
        ["www.alligator.com"]
    ),
    "beaver" : (
        TEST_SNI_CERT_DIRECTORY + "beaver_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "beaver_key.pem",
        ["www.beaver.com"]
    ),
    "many_animals" : (
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_rsa_key.pem",
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
        "com.penguin.macaroni"]
    ),
    "narwhal_cn" : (
        TEST_SNI_CERT_DIRECTORY + "narwhal_cn_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "narwhal_cn_key.pem",
        ["www.narwhal.com"]
    ),
    "octopus_cn_platypus_san" : (
        TEST_SNI_CERT_DIRECTORY + "octopus_cn_platypus_san_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "octopus_cn_platypus_san_key.pem",
        ["www.platypus.com"]
    ),
    "quail_cn_rattlesnake_cn" : (
        TEST_SNI_CERT_DIRECTORY + "quail_cn_rattlesnake_cn_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "quail_cn_rattlesnake_cn_key.pem",
        ["www.quail.com", "www.rattlesnake.com"]
    ),
    "many_animals_mixed_case" : (
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_mixed_case_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_mixed_case_rsa_key.pem",
        ["alligator.com",
        "beaver.com",
        "catFish.com",
        "WWW.dolphin.COM",
        "www.ELEPHANT.com",
        "www.Falcon.Com",
        "WWW.gorilla.COM",
        "www.horse.com",
        "WWW.IMPALA.COM",
        "WwW.jAcKaL.cOm"]
    ),
    "embedded_wildcard" : (
        TEST_SNI_CERT_DIRECTORY + "embedded_wildcard_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "embedded_wildcard_rsa_key.pem",
        ["www.labelstart*labelend.com"]
    ),
    "non_empty_label_wildcard" : (
        TEST_SNI_CERT_DIRECTORY + "non_empty_label_wildcard_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "non_empty_label_wildcard_rsa_key.pem",
        ["WILD*.middle.end"]
    ),
    "trailing_wildcard" : (
        TEST_SNI_CERT_DIRECTORY + "trailing_wildcard_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "trailing_wildcard_rsa_key.pem",
        ["the.prefix.*"]
    ),
    "wildcard_insect" : (
        TEST_SNI_CERT_DIRECTORY + "wildcard_insect_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "wildcard_insect_rsa_key.pem",
        ["ant.insect.hexapod",
        "BEE.insect.hexapod",
        "wasp.INSECT.hexapod",
        "butterfly.insect.hexapod"]
    ),
    "termite" : (
        TEST_SNI_CERT_DIRECTORY + "termite_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "termite_rsa_key.pem",
        [ "termite.insect.hexapod" ]
    ),
    "underwing" : (
        TEST_SNI_CERT_DIRECTORY + "underwing_ecdsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "underwing_ecdsa_key.pem",
        [ "underwing.insect.hexapod" ]
    )
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
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test basic SNI matches for non-default cert.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.beaver.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["beaver"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test default cert is selected when there are no SNI matches.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="not.a.match",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test default cert is selected when no SNI is sent.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni=None,
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test ECDSA cert is selected with matching domain and client only supports ECDSA.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_ECDSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test ECDSA cert selected when: domain matches for both ECDSA+RSA, client supports ECDSA+RSA "\
                    " ciphers, ECDSA is higher priority on server side.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA, Ciphers.ECDHE_ECDSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test domain match is highest priority. Domain matching ECDSA certificate should be selected"\
                    " even if domain mismatched RSA certificate is available and RSA cipher is higher priority.",
        server_certs=[SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA256, Ciphers.ECDHE_ECDSA_AES128_SHA256],
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test certificate with single SAN entry matching is selected before mismatched multi SAN cert",
        server_certs=[SNI_CERTS["many_animals"] , SNI_CERTS["alligator"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
        # many_animals was the first cert added
    MultiCertTest(
        description="Test default cert with multiple sans and no SNI sent.",
        server_certs=[SNI_CERTS["many_animals"] , SNI_CERTS["alligator"]],
        client_sni=None,
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["many_animals"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test certificate match with CN",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["narwhal_cn"] ],
        client_sni="www.narwhal.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["narwhal_cn"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test SAN+CN cert can match using SAN.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["octopus_cn_platypus_san"] ],
        client_sni="www.platypus.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["octopus_cn_platypus_san"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test that CN is not considered for matching if the certificate contains SANs.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["octopus_cn_platypus_san"] ],
        client_sni="www.octopus.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test certificate with multiple CNs can match.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["quail_cn_rattlesnake_cn"] ],
        client_sni="www.rattlesnake.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["quail_cn_rattlesnake_cn"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test cert with embedded wildcard is not treated as a wildcard.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["embedded_wildcard"] ],
        client_sni="www.labelstartWILDCARDlabelend.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test non empty left label wildcard cert is not treated as a wildcard."\
                    " s2n only supports wildcards with a single * as the left label",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["non_empty_label_wildcard"] ],
        client_sni="WILDCARD.middle.end",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test cert with trailing * is not treated as wildcard.",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["trailing_wildcard"] ],
        client_sni="the.prefix.WILDCARD",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Certificate with exact sni match(termite.insect.hexapod) is preferred over wildcard"\
                    " *.insect.hexapod",
        server_certs=[ SNI_CERTS["wildcard_insect"], SNI_CERTS["alligator"], SNI_CERTS["termite"] ],
        client_sni="termite.insect.hexapod",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["termite"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="ECDSA Certificate with exact sni match(underwing.insect.hexapod) is preferred over RSA wildcard"\
                    " *.insect.hexapod when RSA ciphers are higher priority than ECDSA in server preferences.",
        server_certs=[ SNI_CERTS["wildcard_insect"], SNI_CERTS["alligator"], SNI_CERTS["underwing"] ],
        client_sni="underwing.insect.hexapod",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_GCM_SHA256, Ciphers.ECDHE_ECDSA_AES128_GCM_SHA256],
        expected_cert=SNI_CERTS["underwing"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Firstly loaded matching certificate should be selected among certificates with the same domain names",
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["second_alligator_rsa"] ],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.AES128_GCM_SHA256],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Firstly loaded matching certificate should be selected among matching+non-matching certificates",
        server_certs=[ SNI_CERTS["beaver"], SNI_CERTS["alligator"], SNI_CERTS["second_alligator_rsa"] ],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.AES128_GCM_SHA256],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True)]
# Positive test for wildcard matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
        description="Test wildcard *.insect.hexapod matches subdomain " + specific_insect_domain,
        server_certs=[ SNI_CERTS["alligator"], SNI_CERTS["wildcard_insect"] ],
        client_sni=specific_insect_domain,
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["wildcard_insect"],
        expect_matching_hostname=True) for specific_insect_domain in SNI_CERTS["wildcard_insect"][2]])
# Positive test for basic SAN matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
        description="Match SAN " + many_animal_domain + " in many_animals cert",
        server_certs= [ SNI_CERTS["alligator"], SNI_CERTS["many_animals"] ],
        client_sni=many_animal_domain,
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["many_animals"],
        expect_matching_hostname=True) for many_animal_domain in SNI_CERTS["many_animals"][2]])
# Positive test for mixed cased SAN matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
        description="Match SAN " + many_animal_domain + " in many_animals_mixed_case cert",
        server_certs= [SNI_CERTS["alligator"] , SNI_CERTS["many_animals_mixed_case"]],
        client_sni=many_animal_domain,
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["many_animals_mixed_case"],
        expect_matching_hostname=True) for many_animal_domain in SNI_CERTS["many_animals_mixed_case"][2]])
