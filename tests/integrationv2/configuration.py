import threading

from common import Cert, Ciphers, Curves, Protocols, AvailablePorts, TLS_CURVES, TLS13_CURVES
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
ALL_CURVES = TLS13_CURVES[:]
ALL_CURVES.extend(TLS_CURVES)
ALL_CURVES.append(None)


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
    Ciphers.ECDHE_RSA_DES_CBC3_SHA,
    Ciphers.ECDHE_RSA_AES128_SHA256,
    Ciphers.ECDHE_RSA_AES256_SHA384,
    Ciphers.ECDHE_RSA_AES128_GCM_SHA256,
    Ciphers.ECDHE_RSA_AES256_GCM_SHA384,
    Ciphers.ECDHE_RSA_CHACHA20_POLY1305,

    Ciphers.CHACHA20_POLY1305_SHA256,
]


# List of providers that will be tested.
PROVIDERS = [S2N, OpenSSL]


# List of ports available to tests.
available_ports = AvailablePorts()
