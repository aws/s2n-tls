import subprocess
import string
import threading


def invalid_test_parameters(*args, **kwargs):
    """
    Determine if the parameters chosen for a test makes sense.
    This function returns True or False, indicating whether a
    test should be "deselected" based on the arguments.
    """
    protocol = kwargs.get('protocol')
    certificate = kwargs.get('certificate')
    cipher = kwargs.get('cipher')
    curve = kwargs.get('curve')

    if protocol == Protocols.TLS13:
        # TLS1.3 should work with all our certs
        return False

    if protocol != Protocols.TLS13:
        if certificate is not None and 'ecdsa' in certificate.cert:
            # Other protocols don't support the ecdsa cert
            return True

        if cipher in TLS13_CIPHERSUITES:
            return True

        if curve in TLS13_CURVES:
            return True

    return False


def data_bytes(n_bytes):
    """
    Generate bytes to send over the TLS connection.
    These bytes purposefully fall outside of the ascii range
    to prevent triggering "connected commands" present in
    some SSL clients.
    """
    byte_array = [0] * n_bytes
    allowed = [i for i in range(128, 255)]

    j = 0
    for i in range(n_bytes):
        byte_array[i] = allowed[j]
        j += 1
        if j > 126:
            j = 0

    return bytes(byte_array)


class TimeoutException(subprocess.SubprocessError):
    """
    TimeoutException wraps the subprocess class giving more control
    over the formatting of output.
    """
    def __init__(self, timeout_exception):
        self.exception = timeout_exception

    def __str__(self):
        cmd = " ".join(self.exception.cmd)
        return "{} {}".format(self.exception, cmd)


class Curves(object):
    """
    When referencing curves, use these class values.
    Don't hardcode curve names.
    """
    X25519 = "X25519"
    P256 = "P-256"
    P384 = "P-384"


class Ciphersuites(object):
    """
    When referencing ciphersuites, use these class values.
    Don't hardcode the the ciphersuite names.

    The property name will be used to determine which cipher should
    be used by a provider.

    The property value will be displayed in the test output.
    """
    TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"
    TLS_AES_128_GCM_256 = "TLS_AES_128_GCM_256"
    TLS_AES_256_GCM_384 = "TLS_AES_256_GCM_384"


class Protocols(object):
    """
    """
    TLS13 = "TLS1.3"
    TLS12 = "TLS1.2"
    TLS11 = "TLS1.1"
    TLS10 = "TLS1.0"


class Results(object):
    """
    An instance of this object will be returned to the test by a managed_process'
    get_results() method.
    """

    # Byte array containing the standard output of the process
    stdout = None

    # Byte array containing the standard error of the process
    stderr = None

    # Exit code of the process
    exit_code = None

    # Any exception thrown while running the process
    exception = None

    def __init__(self, stdout, stderr, exit_code, exception):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.exception = exception

    def __str__(self):
        return "Stdout: {}\nStderr: {}\nExit code: {}\nException: {}".format(self.stdout, self.stderr, self.exit_code, self.exception)


class ProviderOptions(object):
    def __init__(self,
            mode=None,
            host=None,
            port=None,
            cipher=None,
            curve=None,
            key=None,
            cert=None,
            use_session_ticket=False,
            insecure=False,
            data_to_send=None,
            protocol=None):

        # Client or server
        self.mode = mode

        # Hostname
        self.host = host

        # Port (string because this will be converted to a command line
        self.port = str(port)

        # Cipher suite
        self.cipher = cipher

        # Named curve
        self.curve = curve

        # Path to a key PEM
        self.key = key

        # Path to a certificate PEM
        self.cert = cert

        # Boolean whether to use a resumption ticket
        self.use_session_ticket = use_session_ticket

        # Boolean whether to allow insecure certificates
        self.insecure = insecure

        # Which protocol to use with this provider
        self.protocol = protocol

        # This data will be sent to the peer
        self.data_to_send = data_to_send


class AvailablePorts():
    """
    This iterator will atomically return the next number.
    This is useful when running multiple tests in parallel
    that all need unique port numbers.
    """

    def __init__(self, low=8000, high=20000):
        self.ports = iter(range(low, high))
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        with self.lock:
            return next(self.ports)


# Singleton port provider allowing multiple tests to obtain unique port numbers
available_ports = AvailablePorts()


# Common ciphersuites
TLS_CIPHERSUITES = [
    Ciphersuites.TLS_AES_128_GCM_256,
    Ciphersuites.TLS_AES_256_GCM_384
]


# TLS1.3 specific ciphersuites
TLS13_CIPHERSUITES = [
    Ciphersuites.TLS_CHACHA20_POLY1305_SHA256
]


# Common curves
TLS_CURVES = [
    Curves.P256,
    Curves.P384
]


# TLS1.3 specific curves
TLS13_CURVES = [
    Curves.X25519,
]
