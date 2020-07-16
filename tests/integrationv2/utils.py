from common import Protocols, Curves, Ciphers
from providers import S2N, OpenSSL


def get_expected_s2n_version(protocol, provider):
    """
    s2nd and s2nc print a number for the negotiated TLS version.

    provider is s2n's peer. If s2n tries to speak to s2n < tls13,
    tls12 is always chosen. This is true even when the requested
    protocol is less than tls12.
    """
    if provider == S2N and protocol != Protocols.TLS13:
        version = '33'
    else:
        version = protocol.value

    return version


def get_expected_openssl_version(protocol):
    if protocol == Protocols.TLS13:
        version = 'TLSv1.3'
    elif protocol == Protocols.TLS12:
        version = 'TLSv1.2'
    elif protocol == Protocols.TLS11:
        version = 'TLSv1.1'
    elif protocol == Protocols.TLS10:
        version = 'TLSv1'

    return version


def get_parameter_name(item):
    return str(item)


def invalid_test_parameters(*args, **kwargs):
    """
    Determine if the parameters chosen for a test makes sense.
    This function returns True or False, indicating whether a
    test should be "deselected" based on the arguments.
    """
    protocol = kwargs.get('protocol')
    provider = kwargs.get('provider')
    certificate = kwargs.get('certificate')
    cipher = kwargs.get('cipher')
    curve = kwargs.get('curve')

    if provider is not None and not provider.supports_protocol(protocol):
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

        if provider is not None and not provider.supports_cipher(cipher, with_curve=curve):
            return True

    # If we are using a cipher that depends on a specific certificate algorithm
    # deselect the test of the wrong certificate is used.
    if certificate is not None:
        if protocol is not None and provider.supports_protocol(protocol, with_cert=certificate) is False:
            return True

        if cipher is not None and certificate.compatible_with_cipher(cipher) is False:
            return True

        if curve is not None and certificate.compatible_with_curve(curve) is False:
            return True

    # Prevent situations like using X25519 with TLS1.2
    if curve is not None:
        if protocol is not None and curve.min_protocol > protocol:
            return True

    return False
