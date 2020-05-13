from configuration import TLS13_CURVES
from common import Protocols
from providers import S2N


def get_expected_s2n_version(protocol, provider):
    """
    s2nd and s2nc print a number for the negotiated TLS version.

    provider is s2n's peer. If s2n tries to speak to s2n < tls13,
    tls12 is alway chosen. This is true even when the requested
    protocol is less than tls12.
    """
    if provider == S2N and protocol != Protocols.TLS13:
        version = '33'
    else:
        version = protocol.value

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

    # If the selected protocol doesn't allow the cipher, don't test
    if cipher.min_version > protocol:
        return True

    # NOTE: We don't detect the version of OpenSSL at the moment,
    # so we will deselect these tests.
    if cipher.openssl1_1_1 is False:
        return True

    # If the provider doesn't support the cipher, don't test
    if provider is not None and cipher not in provider.supported_ciphers:
        return True

    # Only test ecdsa ciphers if we are using an ecdsa certificate
    if 'ECDSA' in cipher.name and 'ecdsa' not in certificate.cert:
        return True

    if protocol == Protocols.TLS13:
        # TLS1.3 should work with all our certs
        return False

    if protocol != Protocols.TLS13:

        # Only test the curves when using TLS13
        if curve is not None:
            return True

        if certificate is not None and 'ecdsa' in certificate.cert and 'ECDSA' not in cipher.name:
            return True

        if curve in TLS13_CURVES:
            return True

    return False
