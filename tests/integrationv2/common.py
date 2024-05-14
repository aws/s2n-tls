import os
import re
import subprocess
import threading
import itertools
import random
import string

from constants import TEST_CERT_DIRECTORY
from global_flags import get_flag, S2N_PROVIDER_VERSION


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


def random_str(n):
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def pq_enabled():
    """
    Returns true or false to indicate whether PQ crypto is enabled in s2n
    """
    return "awslc" in get_flag(S2N_PROVIDER_VERSION)


class AvailablePorts(object):
    """
    This iterator will atomically return the next number.
    This is useful when running multiple tests in parallel
    that all need unique port numbers.
    """

    def __init__(self, low=8000, high=30000):
        worker_count = int(os.getenv('PYTEST_XDIST_WORKER_COUNT'))
        chunk_size = int((high - low) / worker_count)

        # If xdist is being used, parse the workerid from the envvar. This can
        # be used to allocate unique ports to each worker.
        worker = os.getenv('PYTEST_XDIST_WORKER')
        worker_id = 0
        if worker is not None:
            worker_id = re.findall(r"gw(\d+)", worker)
            if len(worker_id) != 0:
                worker_id = int(worker_id[0])

        # This is a naive way to allocate ports, but it allows us to cut
        # the run time in half without workers colliding.
        worker_offset = (worker_id * chunk_size)
        base_range = range(low + worker_offset, high)
        wrap_range = range(low, low + worker_offset)
        self.ports = iter(itertools.chain(base_range, wrap_range))

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


class Cert(object):
    def __init__(self, name, prefix, location=TEST_CERT_DIRECTORY):
        self.name = name
        self.cert = location + prefix + "_cert.pem"
        self.key = location + prefix + "_key.pem"
        self.algorithm = 'ANY'
        self.curve = None

        if 'ECDSA' in name:
            self.algorithm = 'EC'
            self.curve = name[-3:]
        elif 'RSA' in name:
            self.algorithm = 'RSA'
        if 'PSS' in name:
            self.algorithm = 'RSAPSS'

    def compatible_with_cipher(self, cipher):
        return (self.algorithm == cipher.algorithm) or (cipher.algorithm == 'ANY')

    def compatible_with_curve(self, curve):
        if self.algorithm != 'EC':
            return True
        return curve.name[-3:] == self.curve

    def compatible_with_sigalg(self, sigalg):
        if self.algorithm != sigalg.algorithm:
            return False
        sig_alg_has_curve = sigalg.algorithm == 'EC' and sigalg.min_protocol == Protocols.TLS13
        if sig_alg_has_curve and self.curve not in sigalg.name:
            return False
        return True

    def __str__(self):
        return self.name


class Certificates(object):
    """
    When referencing certificates, use these values.
    """
    RSA_1024_SHA256 = Cert("RSA_1024_SHA256", "rsa_1024_sha256_client")
    RSA_1024_SHA384 = Cert("RSA_1024_SHA384", "rsa_1024_sha384_client")
    RSA_1024_SHA512 = Cert("RSA_1024_SHA512", "rsa_1024_sha512_client")
    RSA_2048_SHA256 = Cert("RSA_2048_SHA256", "rsa_2048_sha256_client")
    RSA_2048_SHA384 = Cert("RSA_2048_SHA384", "rsa_2048_sha384_client")
    RSA_2048_SHA512 = Cert("RSA_2048_SHA512", "rsa_2048_sha512_client")
    RSA_3072_SHA256 = Cert("RSA_3072_SHA256", "rsa_3072_sha256_client")
    RSA_3072_SHA384 = Cert("RSA_3072_SHA384", "rsa_3072_sha384_client")
    RSA_3072_SHA512 = Cert("RSA_3072_SHA512", "rsa_3072_sha512_client")
    RSA_4096_SHA256 = Cert("RSA_4096_SHA256", "rsa_4096_sha256_client")
    RSA_4096_SHA384 = Cert("RSA_4096_SHA384", "rsa_4096_sha384_client")
    RSA_4096_SHA512 = Cert("RSA_4096_SHA512", "rsa_4096_sha512_client")

    ECDSA_256 = Cert("ECDSA_256", "localhost_ecdsa_p256")
    ECDSA_384 = Cert("ECDSA_384", "ecdsa_p384_pkcs1")
    ECDSA_521 = Cert("ECDSA_521", "ecdsa_p521")

    RSA_2048_SHA256_WILDCARD = Cert(
        "RSA_2048_SHA256_WILDCARD", "rsa_2048_sha256_wildcard")
    RSA_PSS_2048_SHA256 = Cert(
        "RSA_PSS_2048_SHA256", "localhost_rsa_pss_2048_sha256")

    RSA_2048_PKCS1 = Cert("RSA_2048_PKCS1", "rsa_2048_pkcs1")

    OCSP = Cert("OCSP_RSA", "ocsp/server")
    OCSP_ECDSA = Cert("OCSP_ECDSA_256", "ocsp/server_ecdsa")


class Protocol(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __gt__(self, other):
        return self.value > other.value

    def __ge__(self, other):
        return self.value >= other.value

    def __lt__(self, other):
        return self.value < other.value

    def __le__(self, other):
        return self.value <= other.value

    def __eq__(self, other):
        return self.value == other.value

    def __str__(self):
        return self.name


class Protocols(object):
    """
    When referencing protocols, use these protocol values.
    The first argument is the human readable name. The second
    argument is the S2N value. It is used for comparing
    protocols. Since this is hardcoded in S2N, it is not
    expected to change.
    """
    TLS13 = Protocol("TLS1.3", 34)
    TLS12 = Protocol("TLS1.2", 33)
    TLS11 = Protocol("TLS1.1", 32)
    TLS10 = Protocol("TLS1.0", 31)
    SSLv3 = Protocol("SSLv3", 30)


class Cipher(object):
    def __init__(self, name, min_version, openssl1_1_1, fips, parameters=None, iana_standard_name=None, s2n=False, pq=False):
        self.name = name
        self.min_version = min_version
        self.openssl1_1_1 = openssl1_1_1
        self.fips = fips
        self.parameters = parameters
        self.iana_standard_name = iana_standard_name
        self.s2n = s2n
        self.pq = pq

        if self.min_version >= Protocols.TLS13:
            self.algorithm = 'ANY'
        elif iana_standard_name is None:
            self.algorithm = 'ANY'
        elif 'ECDSA' in iana_standard_name:
            self.algorithm = 'EC'
        elif 'RSA' in iana_standard_name:
            self.algorithm = 'RSA'
        else:
            pytest.fail("Unknown signature algorithm on cipher")

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
    DHE_RSA_DES_CBC3_SHA = Cipher("DHE-RSA-DES-CBC3-SHA", Protocols.SSLv3,
                                  False, False, iana_standard_name="SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA")
    DHE_RSA_AES128_SHA = Cipher("DHE-RSA-AES128-SHA", Protocols.SSLv3, True, False, TEST_CERT_DIRECTORY +
                                'dhparams_2048.pem', iana_standard_name="TLS_DHE_RSA_WITH_AES_128_CBC_SHA")
    DHE_RSA_AES256_SHA = Cipher("DHE-RSA-AES256-SHA", Protocols.SSLv3, True, False, TEST_CERT_DIRECTORY +
                                'dhparams_2048.pem', iana_standard_name="TLS_DHE_RSA_WITH_AES_256_CBC_SHA")
    DHE_RSA_AES128_SHA256 = Cipher("DHE-RSA-AES128-SHA256", Protocols.TLS12, True, True, TEST_CERT_DIRECTORY +
                                   'dhparams_2048.pem', iana_standard_name="TLS_DHE_RSA_WITH_AES_128_CBC_SHA256")
    DHE_RSA_AES256_SHA256 = Cipher("DHE-RSA-AES256-SHA256", Protocols.TLS12, True, True, TEST_CERT_DIRECTORY +
                                   'dhparams_2048.pem', iana_standard_name="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256")
    DHE_RSA_AES128_GCM_SHA256 = Cipher("DHE-RSA-AES128-GCM-SHA256", Protocols.TLS12, True, True,
                                       TEST_CERT_DIRECTORY + 'dhparams_2048.pem', iana_standard_name="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256")
    DHE_RSA_AES256_GCM_SHA384 = Cipher("DHE-RSA-AES256-GCM-SHA384", Protocols.TLS12, True, True,
                                       TEST_CERT_DIRECTORY + 'dhparams_2048.pem', iana_standard_name="TLS_DHE_RSA_WITH_AES_256_GCM_SHA384")
    DHE_RSA_CHACHA20_POLY1305 = Cipher("DHE-RSA-CHACHA20-POLY1305", Protocols.TLS12, True, False,
                                       TEST_CERT_DIRECTORY + 'dhparams_2048.pem', iana_standard_name="TLS_DHE_RSA_WITH_AES_256_GCM_SHA384")

    AES128_SHA = Cipher("AES128-SHA", Protocols.SSLv3, True,
                        True, iana_standard_name="TLS_RSA_WITH_AES_128_CBC_SHA")
    AES256_SHA = Cipher("AES256-SHA", Protocols.SSLv3, True,
                        True, iana_standard_name="TLS_RSA_WITH_AES_256_CBC_SHA")
    AES128_SHA256 = Cipher("AES128-SHA256", Protocols.TLS12, True,
                           True, iana_standard_name="TLS_RSA_WITH_AES_128_CBC_SHA256")
    AES256_SHA256 = Cipher("AES256-SHA256", Protocols.TLS12, True,
                           True, iana_standard_name="TLS_RSA_WITH_AES_256_CBC_SHA256")
    AES128_GCM_SHA256 = Cipher("TLS_AES_128_GCM_SHA256", Protocols.TLS13,
                               True, True, iana_standard_name="TLS_AES_128_GCM_SHA256")
    AES256_GCM_SHA384 = Cipher("TLS_AES_256_GCM_SHA384", Protocols.TLS13,
                               True, True, iana_standard_name="TLS_AES_256_GCM_SHA384")

    ECDHE_ECDSA_AES128_SHA = Cipher("ECDHE-ECDSA-AES128-SHA", Protocols.SSLv3,
                                    True, False, iana_standard_name="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
    ECDHE_ECDSA_AES256_SHA = Cipher("ECDHE-ECDSA-AES256-SHA", Protocols.SSLv3,
                                    True, False, iana_standard_name="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")
    ECDHE_ECDSA_AES128_SHA256 = Cipher("ECDHE-ECDSA-AES128-SHA256", Protocols.TLS12,
                                       True, True, iana_standard_name="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256")
    ECDHE_ECDSA_AES256_SHA384 = Cipher("ECDHE-ECDSA-AES256-SHA384", Protocols.TLS12,
                                       True, True, iana_standard_name="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384")
    ECDHE_ECDSA_AES128_GCM_SHA256 = Cipher("ECDHE-ECDSA-AES128-GCM-SHA256", Protocols.TLS12,
                                           True, True, iana_standard_name="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
    ECDHE_ECDSA_AES256_GCM_SHA384 = Cipher("ECDHE-ECDSA-AES256-GCM-SHA384", Protocols.TLS12,
                                           True, True, iana_standard_name="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
    ECDHE_ECDSA_CHACHA20_POLY1305 = Cipher("ECDHE-ECDSA-CHACHA20-POLY1305", Protocols.TLS12,
                                           True, False, iana_standard_name="TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")

    ECDHE_RSA_DES_CBC3_SHA = Cipher("ECDHE-RSA-DES-CBC3-SHA", Protocols.SSLv3,
                                    False, False, iana_standard_name="TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")
    ECDHE_RSA_AES128_SHA = Cipher("ECDHE-RSA-AES128-SHA", Protocols.SSLv3,
                                  True, False, iana_standard_name="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
    ECDHE_RSA_AES256_SHA = Cipher("ECDHE-RSA-AES256-SHA", Protocols.SSLv3,
                                  True, False, iana_standard_name="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
    ECDHE_RSA_RC4_SHA = Cipher("ECDHE-RSA-RC4-SHA", Protocols.SSLv3,
                               False, False, iana_standard_name="TLS_ECDHE_RSA_WITH_RC4_128_SHA")
    ECDHE_RSA_AES128_SHA256 = Cipher("ECDHE-RSA-AES128-SHA256", Protocols.TLS12,
                                     True, True, iana_standard_name="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
    ECDHE_RSA_AES256_SHA384 = Cipher("ECDHE-RSA-AES256-SHA384", Protocols.TLS12,
                                     True, True, iana_standard_name="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")
    ECDHE_RSA_AES128_GCM_SHA256 = Cipher("ECDHE-RSA-AES128-GCM-SHA256", Protocols.TLS12,
                                         True, True, iana_standard_name="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    ECDHE_RSA_AES256_GCM_SHA384 = Cipher("ECDHE-RSA-AES256-GCM-SHA384", Protocols.TLS12,
                                         True, True, iana_standard_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    ECDHE_RSA_CHACHA20_POLY1305 = Cipher("ECDHE-RSA-CHACHA20-POLY1305", Protocols.TLS12,
                                         True, False, iana_standard_name="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
    CHACHA20_POLY1305_SHA256 = Cipher("TLS_CHACHA20_POLY1305_SHA256", Protocols.TLS13,
                                      True, False, iana_standard_name="TLS_CHACHA20_POLY1305_SHA256")

    KMS_TLS_1_0_2018_10 = Cipher(
        "KMS-TLS-1-0-2018-10", Protocols.TLS10, False, False, s2n=True)
    KMS_PQ_TLS_1_0_2019_06 = Cipher(
        "KMS-PQ-TLS-1-0-2019-06", Protocols.TLS10, False, False, s2n=True, pq=True)
    KMS_PQ_TLS_1_0_2020_02 = Cipher(
        "KMS-PQ-TLS-1-0-2020-02", Protocols.TLS10, False, False, s2n=True, pq=True)
    KMS_PQ_TLS_1_0_2020_07 = Cipher(
        "KMS-PQ-TLS-1-0-2020-07", Protocols.TLS10, False, False, s2n=True, pq=True)
    PQ_SIKE_TEST_TLS_1_0_2019_11 = Cipher(
        "PQ-SIKE-TEST-TLS-1-0-2019-11", Protocols.TLS10, False, False, s2n=True, pq=True)
    PQ_SIKE_TEST_TLS_1_0_2020_02 = Cipher(
        "PQ-SIKE-TEST-TLS-1-0-2020-02", Protocols.TLS10, False, False, s2n=True, pq=True)
    PQ_TLS_1_0_2020_12 = Cipher(
        "PQ-TLS-1-0-2020-12", Protocols.TLS10, False, False, s2n=True, pq=True)
    PQ_TLS_1_0_2023_01 = Cipher(
        "PQ-TLS-1-0-2023-01-24", Protocols.TLS10, False, False, s2n=True, pq=True)
    PQ_TLS_1_3_2023_06_01 = Cipher(
        "PQ-TLS-1-3-2023-06-01", Protocols.TLS12, False, False, s2n=True, pq=True)

    SECURITY_POLICY_20210816 = Cipher(
        "20210816", Protocols.TLS12, False, False, s2n=True, pq=False)

    @staticmethod
    def from_iana(iana_name):
        ciphers = [
            cipher for attr in vars(Ciphers)
            if not callable(cipher := getattr(Ciphers, attr))
            and not attr.startswith("_")
            and cipher.iana_standard_name
        ]
        return {
            cipher.iana_standard_name: cipher
            for cipher in ciphers
        }.get(iana_name)


class Curve(object):
    def __init__(self, name, min_protocol=Protocols.SSLv3):
        self.name = name
        self.min_protocol = min_protocol

    def __str__(self):
        return self.name


class Curves(object):
    """
    When referencing curves, use these class values.
    Don't hardcode curve names.
    """
    X25519 = Curve("X25519", Protocols.TLS13)
    P256 = Curve("P-256")
    # Our only SSLv3 provider doesn't support extensions
    # so there is no way to negotiate a curve other than the
    # default P-256 in SSLv3.
    P384 = Curve("P-384", Protocols.TLS10)
    P521 = Curve("P-521", Protocols.TLS10)
    SecP256r1Kyber768Draft00 = Curve("SecP256r1Kyber768Draft00")
    X25519Kyber768Draft00 = Curve("X25519Kyber768Draft00")

    @staticmethod
    def from_name(name):
        curves = [
            curve for attr in vars(Curves)
            if not callable(curve := getattr(Curves, attr))
            and not attr.startswith("_")
            and curve.name
        ]
        return {
            curve.name: curve
            for curve in curves
        }.get(name)


class KemGroup(object):
    def __init__(self, oqs_name):
        self.oqs_name = oqs_name

    def __str__(self):
        return self.oqs_name


class KemGroups(object):
    # Though s2n and oqs_openssl 3.x support KEM groups with 128-bit security
    # ECC + Kyber >512, oqs_openssl 1.1.1 does not:
    #
    # https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-kem-info.md
    X25519_KYBER512R3 = KemGroup("X25519_kyber512")
    P256_KYBER512R3 = KemGroup("p256_kyber512")
    P384_KYBER768R3 = KemGroup("p384_kyber768")
    P521_KYBER1024R3 = KemGroup("p521_kyber1024")
    SecP256r1Kyber768Draft00 = KemGroup("SecP256r1Kyber768Draft00")
    X25519Kyber768Draft00 = KemGroup("X25519Kyber768Draft00")


class Signature(object):
    def __init__(self, name, min_protocol=Protocols.SSLv3, max_protocol=Protocols.TLS13, sig_type=None, sig_digest=None):
        self.min_protocol = min_protocol
        self.max_protocol = max_protocol

        if 'RSA' in name.upper():
            self.algorithm = 'RSA'
        if 'PSS_PSS' in name.upper():
            self.algorithm = 'RSAPSS'
        if 'EC' in name.upper() or 'ED' in name.upper():
            self.algorithm = 'EC'

        if not (sig_type or sig_digest) and '+' in name:
            sig_type, sig_digest = name.split('+')

        self.name = name

        self.sig_type = sig_type
        self.sig_digest = sig_digest

    def __str__(self):
        return self.name


class Signatures(object):
    RSA_SHA1 = Signature('RSA+SHA1',   max_protocol=Protocols.TLS12)
    RSA_SHA224 = Signature('RSA+SHA224', max_protocol=Protocols.TLS12)
    RSA_SHA256 = Signature('RSA+SHA256', max_protocol=Protocols.TLS12)
    RSA_SHA384 = Signature('RSA+SHA384', max_protocol=Protocols.TLS12)
    RSA_SHA512 = Signature('RSA+SHA512', max_protocol=Protocols.TLS12)
    RSA_MD5_SHA1 = Signature('RSA+MD5_SHA1', max_protocol=Protocols.TLS11)
    ECDSA_SHA224 = Signature('ECDSA+SHA224', max_protocol=Protocols.TLS12)
    ECDSA_SHA256 = Signature('ECDSA+SHA256', max_protocol=Protocols.TLS12)
    ECDSA_SHA384 = Signature('ECDSA+SHA384', max_protocol=Protocols.TLS12)
    ECDSA_SHA512 = Signature('ECDSA+SHA512', max_protocol=Protocols.TLS12)
    ECDSA_SHA1 = Signature('ECDSA+SHA1', max_protocol=Protocols.TLS12)

    RSA_PSS_RSAE_SHA256 = Signature(
        'RSA-PSS+SHA256',
        sig_type='RSA-PSS-RSAE',
        sig_digest='SHA256')

    RSA_PSS_PSS_SHA256 = Signature(
        'rsa_pss_pss_sha256',
        min_protocol=Protocols.TLS13,
        sig_type='RSA-PSS-PSS',
        sig_digest='SHA256')

    ECDSA_SECP256r1_SHA256 = Signature(
        'ecdsa_secp256r1_sha256',
        min_protocol=Protocols.TLS13,
        sig_type='ECDSA',
        sig_digest='SHA256')
    ECDSA_SECP384r1_SHA384 = Signature(
        'ecdsa_secp384r1_sha384',
        min_protocol=Protocols.TLS13,
        sig_type='ECDSA',
        sig_digest='SHA384')
    ECDSA_SECP521r1_SHA512 = Signature(
        'ecdsa_secp521r1_sha512',
        min_protocol=Protocols.TLS13,
        sig_type='ECDSA',
        sig_digest='SHA512')


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

    def __init__(self, stdout, stderr, exit_code, exception, expect_stderr=False, expect_nonzero_exit=False):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.exception = exception
        self.expect_stderr = expect_stderr
        self.expect_nonzero_exit = expect_nonzero_exit

    def __str__(self):
        return "Stdout: {}\nStderr: {}\nExit code: {}\nException: {}".format(self.stdout, self.stderr, self.exit_code, self.exception)

    def assert_success(self):
        assert self.exception is None, self.exception
        if not self.expect_nonzero_exit:
            assert self.exit_code == 0, f"exit code: {self.exit_code}"
        if not self.expect_stderr:
            assert not self.stderr, self.stderr

    def output_streams(self):
        return {self.stdout, self.stderr}


class ProviderOptions(object):
    def __init__(
            self,
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
            extra_flags=None,
            trust_store=None,
            reconnects_before_exit=None,
            reconnect=None,
            verify_hostname=None,
            server_name=None,
            protocol=None,
            use_mainline_version=None,
            env_overrides=dict(),
            enable_client_ocsp=False,
            ocsp_response=None,
            signature_algorithm=None,
            record_size=None,
            verbose=True
    ):

        # Client or server
        self.mode = mode

        # Hostname
        self.host = host
        if not self.host:
            self.host = "localhost"

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

        self.trust_store = trust_store

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

        # Reconnects on the server side (includes first connection)
        self.reconnects_before_exit = reconnects_before_exit

        # Tell the client to reconnect
        self.reconnect = reconnect

        # Tell the client to verify that the hostname returned by the server
        # matches this argument
        self.verify_hostname = verify_hostname

        # Tell the client to send this server name to the server
        self.server_name = server_name

        # Extra flags to pass to the provider
        self.extra_flags = extra_flags

        # Boolean whether the provider is an older version of s2n
        self.use_mainline_version = use_mainline_version

        # Extra environment parameters
        self.env_overrides = env_overrides

        # Enable OCSP on the client
        self.enable_client_ocsp = enable_client_ocsp

        # Path to OCSP response on the server
        self.ocsp_response = ocsp_response

        self.signature_algorithm = signature_algorithm

        self.record_size = record_size

        # How verbose should the provider be when printing to stdout?
        # Default to more information, leave the option for less.
        # Useful if you find that debugging information is printed between
        # application data you expect the provider to print on stdout.
        self.verbose = verbose
