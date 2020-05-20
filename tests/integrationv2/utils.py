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

    if cipher is not None:
        # If the selected protocol doesn't allow the cipher, don't test
        if protocol is not None and cipher.min_version > protocol:
            return True

        # NOTE: We don't detect the version of OpenSSL at the moment,
        # so we will deselect these tests.
        if cipher.openssl1_1_1 is False:
            return True

    # If we are using a cipher that depends on a specific certificate algorithm
    # deselect the test of the wrong certificate is used.
    if certificate is not None:
        if cipher is not None and certificate.compatible_with_cipher(cipher) is False:
            return True

        if curve is not None and certificate.compatible_with_curve(curve) is False:
            return True

    # Prevent situations like using X25519 with TLS1.2
    if curve is not None and protocol is not None and curve.min_protocol > protocol:
            return True

    return False
