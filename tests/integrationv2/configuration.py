import threading

from certificate import Cert
from common import Ciphersuites, Curves, Protocols, AvailablePorts, TLS_CIPHERSUITES, TLS13_CIPHERSUITES, TLS_CURVES, TLS13_CURVES
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


# List of all ciphersuites that will be tested.
ALL_CIPHERSUITES = TLS13_CIPHERSUITES[:]
ALL_CIPHERSUITES.extend(TLS_CIPHERSUITES)


# List of all curves that will be tested.
ALL_CURVES = TLS13_CURVES[:]
ALL_CURVES.extend(TLS_CURVES)


ALL_CERTS = [
    # PKCS1 will only work with older OpenSSL versions
    # Cert("RSA_2048_PKCS1", "rsa_2048_pkcs1"),
    Cert("RSA_1024_SHA256", "rsa_1024_sha256_client"),
    Cert("RSA_1024_SHA384", "rsa_1024_sha384_client"),
    Cert("RSA_1024_SHA512", "rsa_1024_sha512_client"),
    Cert("RSA_2048_SHA256", "rsa_2048_sha256_client"),
    Cert("RSA_2048_SHA384", "rsa_2048_sha384_client"),
    Cert("RSA_2048_SHA512", "rsa_2048_sha512_client"),
    Cert("RSA_3072_SHA256", "rsa_3072_sha256_client"),
    Cert("RSA_3072_SHA384", "rsa_3072_sha384_client"),
    Cert("RSA_3072_SHA512", "rsa_3072_sha512_client"),
    Cert("RSA_4096_SHA256", "rsa_4096_sha256_client"),
    Cert("RSA_4096_SHA384", "rsa_4096_sha384_client"),
    Cert("RSA_4096_SHA512", "rsa_4096_sha512_client"),
    Cert("ECDSA_256", "ecdsa_p256_pkcs1"),
    Cert("ECDSA_384", "ecdsa_p384_pkcs1"),
]


# List of providers that will be tested.
PROVIDERS = [S2N, OpenSSL]


available_ports = AvailablePorts()
