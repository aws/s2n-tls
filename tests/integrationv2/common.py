import subprocess
import string
import threading

from constants import TEST_CERT_DIRECTORY


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


class AvailablePorts():
    """
    This iterator will atomically return the next number.
    This is useful when running multiple tests in parallel
    that all need unique port numbers.
    """

    def __init__(self, low=8000, high=30000):
        self.ports = iter(range(low, high))
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        with self.lock:
            return next(self.ports)


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


class Cert():
    def __init__(self, name, prefix, location=TEST_CERT_DIRECTORY):
        self.name = name
        self.cert = location + prefix + "_cert.pem"
        self.key = location + prefix + "_key.pem"

    def __str__(self):
        return self.name


class Protocol(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __gt__(self, other):
        return self.value > other.value

    def __lt__(self, other):
        return self.value < other.value

    def __eq__(self, other):
        return self.value == other.value

    def __str__(self):
        return self.name


class Protocols(object):
    """
    When referencing protocols, use these protocol values.
    """
    TLS13 = Protocol("TLS1.3", 34)
    TLS12 = Protocol("TLS1.2", 33)
    TLS11 = Protocol("TLS1.1", 32)
    TLS10 = Protocol("TLS1.0", 31)
    SSLv3 = Protocol("SSLv3", 30)


class Cipher(object):
    def __init__(self, name, min_version, compat, compat2):
        self.name = name
        self.min_version = min_version
        self.compat = compat

    def __eq__(self, other):
        return self.name == other

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name


class Ciphers(object):
    """
    When referencing ciphers, use these class values.
    """
    RC4_MD5 = Cipher("RC4_MD5", Protocols.SSLv3, False, False)
    RC4_SHA = Cipher("RC4_SHA", Protocols.SSLv3, False, False)
    DES_CBC3_SHA = Cipher("DES_CBC3_SHA", Protocols.SSLv3, False, True)
    DHE_RSA_DES_CBC3_SHA = Cipher("DHE_RSA_DES_CBC3_SHA", Protocols.SSLv3, False, False)
    AES128_SHA = Cipher("AES128_SHA", Protocols.SSLv3, True, True)
    DHE_RSA_AES128_SHA = Cipher("DHE_RSA_AES128_SHA", Protocols.SSLv3, True, False)
    AES256_SHA = Cipher("AES256_SHA", Protocols.SSLv3, True, True)
    DHE_RSA_AES256_SHA = Cipher("DHE_RSA_AES256_SHA", Protocols.SSLv3, True, False)
    AES128_SHA256 = Cipher("AES128_SHA256", Protocols.TLS12, True, True)
    AES256_SHA256 = Cipher("AES256_SHA256", Protocols.TLS12, True, True)
    DHE_RSA_AES128_SHA256 = Cipher("DHE_RSA_AES128_SHA256", Protocols.TLS12, True, True)
    DHE_RSA_AES256_SHA256 = Cipher("DHE_RSA_AES256_SHA256", Protocols.TLS12, True, True)
    AES128_GCM_SHA256 = Cipher("AES128_GCM_SHA256", Protocols.TLS13, True, True)
    AES256_GCM_SHA384 = Cipher("AES256_GCM_SHA384", Protocols.TLS13, True, True)
    DHE_RSA_AES128_GCM_SHA256 = Cipher("DHE_RSA_AES128_GCM_SHA256", Protocols.TLS12, True, True)
    DHE_RSA_AES256_GCM_SHA384 = Cipher("DHE_RSA_AES256_GCM_SHA384", Protocols.TLS12, True, True)
    #ECDHE_ECDSA_AES128_SHA = Cipher("ECDHE_ECDSA_AES128_SHA", Protocols.SSLv3, True, False)
    #ECDHE_ECDSA_AES256_SHA = Cipher("ECDHE_ECDSA_AES256_SHA", Protocols.SSLv3, True, False)
    #ECDHE_ECDSA_AES128_SHA256 = Cipher("ECDHE_ECDSA_AES128_SHA256", Protocols.TLS12, True, True)
    #ECDHE_ECDSA_AES256_SHA384 = Cipher("ECDHE_ECDSA_AES256_SHA384", Protocols.TLS12, True, True)
    ECDHE_ECDSA_AES128_GCM_SHA256 = Cipher("ECDHE_ECDSA_AES128_GCM_SHA256", Protocols.TLS12, True, True)
    ECDHE_ECDSA_AES256_GCM_SHA384 = Cipher("ECDHE_ECDSA_AES256_GCM_SHA384", Protocols.TLS12, True, True)
    ECDHE_RSA_DES_CBC3_SHA = Cipher("ECDHE_RSA_DES_CBC3_SHA", Protocols.SSLv3, False, False)
    ECDHE_RSA_AES128_SHA = Cipher("ECDHE_RSA_AES128_SHA", Protocols.SSLv3, True, False)
    ECDHE_RSA_AES256_SHA = Cipher("ECDHE_RSA_AES256_SHA", Protocols.SSLv3, True, False)
    ECDHE_RSA_RC4_SHA = Cipher("ECDHE_RSA_RC4_SHA", Protocols.SSLv3, False, False)
    ECDHE_RSA_AES128_SHA256 = Cipher("ECDHE_RSA_AES128_SHA256", Protocols.TLS12, True, True)
    ECDHE_RSA_AES256_SHA384 = Cipher("ECDHE_RSA_AES256_SHA384", Protocols.TLS12, True, True)
    ECDHE_RSA_AES128_GCM_SHA256 = Cipher("ECDHE_RSA_AES128_GCM_SHA256", Protocols.TLS12, True, True)
    ECDHE_RSA_AES256_GCM_SHA384 = Cipher("ECDHE_RSA_AES256_GCM_SHA384", Protocols.TLS12, True, True)
    ECDHE_RSA_CHACHA20_POLY1305 = Cipher("ECDHE_RSA_CHACHA20_POLY1305", Protocols.TLS12, True, False)
    ECDHE_ECDSA_CHACHA20_POLY1305 = Cipher("ECDHE_ECDSA_CHACHA20_POLY1305", Protocols.TLS12, True, False)
    DHE_RSA_CHACHA20_POLY1305 = Cipher("DHE_RSA_CHACHA20_POLY1305", Protocols.TLS12, True, False)
    CHACHA20_POLY1305_SHA256 = Cipher("CHACHA20_POLY1305_SHA256", Protocols.TLS13, True, False)


class Curves(object):
    """
    When referencing curves, use these class values.
    Don't hardcode curve names.
    """
    X25519 = "X25519"
    P256 = "P-256"
    P384 = "P-384"


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
            use_client_auth=False,
            client_key_file=None,
            client_certificate_file=None,
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

        # Parameters to configure client authentication
        self.use_client_auth = use_client_auth
        self.client_certificate_file = client_certificate_file
        self.client_key_file = client_key_file

# Common curves
TLS_CURVES = [
    Curves.P256,
    Curves.P384
]


# TLS1.3 specific curves
TLS13_CURVES = [
    Curves.X25519,
]
