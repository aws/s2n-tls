# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from common import Protocols
from providers import S2N, SSLv3Provider
from global_flags import get_flag, S2N_FIPS_MODE


def to_bytes(val):
    return bytes(str(val).encode("utf-8"))


def to_string(val: bytes):
    return val.decode(encoding="ascii", errors="backslashreplace")


def get_expected_s2n_version(protocol, provider):
    """
    s2nd and s2nc print a number for the negotiated TLS version.

    provider is s2n's peer. If s2n tries to speak to s2n < tls13,
    tls12 is always chosen. This is true even when the requested
    protocol is less than tls12.
    """
    if provider == S2N and protocol != Protocols.TLS13:
        version = "33"
    else:
        version = protocol.value

    return version


def get_expected_openssl_version(protocol):
    return {
        Protocols.TLS10.value: "TLSv1",
        Protocols.TLS11.value: "TLSv1.1",
        Protocols.TLS12.value: "TLSv1.2",
        Protocols.TLS13.value: "TLSv1.3",
    }.get(protocol.value)


def get_expected_gnutls_version(protocol):
    return {
        Protocols.TLS10.value: "TLS1.0",
        Protocols.TLS11.value: "TLS1.1",
        Protocols.TLS12.value: "TLS1.2",
        Protocols.TLS13.value: "TLS1.3",
    }.get(protocol.value)


def get_parameter_name(item):
    if isinstance(item, type):
        return item.__name__
    return str(item)


# Cached variable to avoid repeatedly checking the filesystem
_SSLV3_PROVIDER_AVAILABLE = None

def _is_sslv3_provider_available():
    """
    Check if SSLv3Provider's requirements are available in the current environment.
    
    SSLv3Provider requires a specific OpenSSL 1.0.2 installation, which should be
    specified via environment variables OPENSSL_1_0_2_INSTALL_DIR or 
    OPENSSL_1_0_2_FIPS_INSTALL_DIR. This function checks if these variables are
    set and if the specified directory exists.
    
    Returns:
        bool: True if the SSLv3Provider can be used, False otherwise.
    """
    global _SSLV3_PROVIDER_AVAILABLE
    if _SSLV3_PROVIDER_AVAILABLE is None:
        install_dir = os.getenv("OPENSSL_1_0_2_INSTALL_DIR") or os.getenv("OPENSSL_1_0_2_FIPS_INSTALL_DIR")
        _SSLV3_PROVIDER_AVAILABLE = install_dir is not None and os.path.exists(install_dir)
    return _SSLV3_PROVIDER_AVAILABLE


def invalid_test_parameters(*args, **kwargs):
    """
    Determine if the parameters chosen for a test makes sense.
    This function returns True or False, indicating whether a
    test should be "deselected" based on the arguments.
    """
    protocol = kwargs.get("protocol")
    provider = kwargs.get("provider")
    other_provider = kwargs.get("other_provider")
    certificate = kwargs.get("certificate")
    client_certificate = kwargs.get("client_certificate")
    cipher = kwargs.get("cipher")
    curve = kwargs.get("curve")
    signature = kwargs.get("signature")

    providers = [provider_ for provider_ in [provider, other_provider] if provider_]
    # Always consider S2N
    providers.append(S2N)
    
    # Check if SSLv3Provider is requested but not available
    # This allows tests to be skipped early if the required OpenSSL 1.0.2 installation
    # is not available, rather than failing during test execution.
    if any(provider_ == SSLv3Provider for provider_ in providers) and not _is_sslv3_provider_available():
        return True

    certificates = [cert for cert in [certificate, client_certificate] if cert]

    # Older versions do not support RSA-PSS-PSS certificates
    if protocol and protocol < Protocols.TLS12:
        if client_certificate and client_certificate.algorithm == "RSAPSS":
            return True
        if certificate and certificate.algorithm == "RSAPSS":
            return True

    for provider_ in providers:
        if not provider_.supports_protocol(protocol):
            return True

        for certificate_ in certificates:
            if not provider_.supports_certificate(certificate_):
                return True

    if cipher is not None:
        # If the selected protocol doesn't allow the cipher, don't test
        if protocol is not None:
            if cipher.min_version > protocol:
                return True

            # Ciphersuites prior to TLS13 can not be used with TLS13
            # https://wiki.openssl.org/index.php/TLS1.3#Differences_with_TLS1.2_and_below
            if protocol is Protocols.TLS13 and cipher.min_version < protocol:
                return True

        for provider_ in providers:
            if not provider_.supports_cipher(cipher, with_curve=curve):
                return True

        if get_flag(S2N_FIPS_MODE):
            if not cipher.fips:
                return True

    # If we are using a cipher that depends on a specific certificate algorithm
    # deselect the test if the wrong certificate is used.
    if certificate is not None:
        if cipher is not None and certificate.compatible_with_cipher(cipher) is False:
            return True

    # If the curve is specified, then all signatures must use that curve
    if curve:
        if certificate and not certificate.compatible_with_curve(curve):
            return True
        if client_certificate and not client_certificate.compatible_with_curve(curve):
            return True

    # Prevent situations like using X25519 with TLS1.2
    if curve is not None:
        if protocol is not None and curve.min_protocol > protocol:
            return True

    if signature is not None:
        for provider_ in providers:
            if provider_.supports_signature(signature) is False:
                return True

    return False
