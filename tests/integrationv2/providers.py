import pytest
import threading

from common import ProviderOptions, Ciphers, Curves, Protocols, Certificates
from global_flags import get_flag, S2N_PROVIDER_VERSION


class Provider(object):
    """
    A provider defines a specific provider of TLS. This could be
    S2N, OpenSSL, BoringSSL, etc.
    """

    ClientMode = "client"
    ServerMode = "server"

    def __init__(self, options: ProviderOptions):
        # If the test should wait for a specific output message before beginning,
        # put that message in ready_to_test_marker
        self.ready_to_test_marker = None

        # If the test should wait for a specific output message before sending
        # data, put that message in ready_to_send_input_marker
        self.ready_to_send_input_marker = None

        # Allows users to determine if the provider is ready to begin testing
        self._provider_ready_condition = threading.Condition()
        self._provider_ready = False

        if type(options) is not ProviderOptions:
            raise TypeError

        self.options = options
        if self.options.mode == Provider.ServerMode:
            self.cmd_line = self.setup_server()
        elif self.options.mode == Provider.ClientMode:
            self.cmd_line = self.setup_client()

    def setup_client(self):
        """
        Provider specific setup code goes here.
        This will probably include creating the command line based on ProviderOptions.
        """
        raise NotImplementedError

    def setup_server(self):
        """
        Provider specific setup code goes here.
        This will probably include creating the command line based on ProviderOptions.
        """
        raise NotImplementedError


    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        raise NotImplementedError

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        raise NotImplementedError

    def get_cmd_line(self):
        return self.cmd_line

    def is_provider_ready(self):
        return self._provider_ready is True

    def set_provider_ready(self):
        with self._provider_ready_condition:
            self._provider_ready = True
            self._provider_ready_condition.notify()


class Tcpdump(Provider):
    """
    TcpDump is used by the dynamic record test. It only needs to watch
    a handful of packets before it can exit.

    This class still follows the provider setup, but all values are hardcoded
    because this isn't expected to be used outside of the dynamic record test.
    """
    def __init__(self, options: ProviderOptions):
        Provider.__init__(self, options)

    def setup_client(self):
        self.ready_to_test_marker = 'listening on lo'
        tcpdump_filter = "dst port {}".format(self.options.port)

        cmd_line = ["tcpdump",
            # Line buffer the output
            "-l",

            # Only read 10 packets before exiting. This is enough to find a large
            # packet, and still exit before the timeout.
            "-c", "10",

            # Watch the loopback device
            "-i", "lo",

            # Don't resolve IP addresses
            "-nn",

            # Set the buffer size to 1k
            "-B", "1024",
            tcpdump_filter]

        return cmd_line


class S2N(Provider):
    """
    The S2N provider translates flags into s2nc/s2nd command line arguments.
    """
    def __init__(self, options: ProviderOptions):
        self.ready_to_send_input_marker = None
        Provider.__init__(self, options)

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        # If s2n is built with OpenSSL 1.0.2 it can't connect to itself
        if protocol is Protocols.TLS13 and 'openssl-1.0.2' in OpenSSL.get_version():
            if with_cert is not None and with_cert.algorithm != 'EC':
                return False

        return True

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        return True

    def setup_client(self):
        """
        Using the passed ProviderOptions, create a command line.
        """
        cmd_line = ['s2nc', '--non-blocking']

        # Tests requiring reconnects can't wait on echo data,
        # but all other tests can.
        if self.options.reconnect is not True:
            cmd_line.append('-e')

        # This is the last thing printed by s2nc before it is ready to send/receive data
        self.ready_to_send_input_marker = 'Ready to send'

        if self.options.use_session_ticket is False:
            cmd_line.append('-T')

        if self.options.insecure is True:
            cmd_line.append('--insecure')
        elif self.options.trust_store:
            cmd_line.extend(['-f', self.options.trust_store])
        elif self.options.cert:
            cmd_line.extend(['-f', self.options.cert])

        if self.options.reconnect is True:
            cmd_line.append('-r')

        # If the test provided a cipher (security policy) that is compatible with
        # s2n, we'll use it. Otherwise, default to the appropriate `test_all` policy.
        cipher_prefs = 'test_all_tls12'
        if self.options.protocol is Protocols.TLS13:
            cipher_prefs = 'test_all'
        if self.options.cipher and self.options.cipher.s2n:
            cipher_prefs = self.options.cipher.name

        cmd_line.extend(['-c', cipher_prefs])

        if self.options.use_client_auth:
            if self.options.key:
                cmd_line.extend(['--key', self.options.key])
            if self.options.cert:
                cmd_line.extend(['--cert', self.options.cert])

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        cmd_line.extend([self.options.host, self.options.port])

        # Clients are always ready to connect
        self.set_provider_ready()

        return cmd_line

    def setup_server(self):
        """
        Using the passed ProviderOptions, create a command line.
        """
        cmd_line = ['s2nd', '-X', '--self-service-blinding', '--non-blocking']

        if self.options.key is not None:
            cmd_line.extend(['--key', self.options.key])
        if self.options.cert is not None:
            cmd_line.extend(['--cert', self.options.cert])

        if self.options.insecure is True:
            cmd_line.append('--insecure')
        elif self.options.trust_store:
            cmd_line.extend(['-t', self.options.trust_store])
        elif self.options.cert:
            cmd_line.extend(['-t', self.options.cert])

        # If the test provided a cipher (security policy) that is compatible with
        # s2n, we'll use it. Otherwise, default to the appropriate `test_all` policy.
        cipher_prefs = 'test_all_tls12'
        if self.options.protocol is Protocols.TLS13:
            cipher_prefs = 'test_all'
        if self.options.cipher and self.options.cipher.s2n:
            cipher_prefs = self.options.cipher.name

        cmd_line.extend(['-c', cipher_prefs])

        if self.options.use_client_auth is True:
            cmd_line.append('-m')

        if self.options.use_session_ticket is False:
            cmd_line.append('-T')

        if self.options.reconnects_before_exit is not None:
            cmd_line.append('--max-conns={}'.format(self.options.reconnects_before_exit))

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        cmd_line.extend([self.options.host, self.options.port])

        return cmd_line


class OpenSSL(Provider):

    _version = get_flag(S2N_PROVIDER_VERSION)

    def __init__(self, options: ProviderOptions):
        self.ready_to_send_input_marker = None
        Provider.__init__(self, options)

    def _join_ciphers(self, ciphers):
        """
        Given a list of ciphers, join the names with a ':' like OpenSSL expects
        """
        assert type(ciphers) is list

        cipher_list = []
        for c in ciphers:
            cipher_list.append(c.name)

        ciphers = ':'.join(cipher_list)

        return ciphers

    def _cipher_to_cmdline(self, cipher):
        cmdline = list()

        ciphers = []
        if type(cipher) is list:
            # In the case of a cipher list we need to be sure TLS13 specific ciphers aren't
            # mixed with ciphers from previous versions
            is_tls13_or_above = (cipher[0].min_version >= Protocols.TLS13)
            mismatch = [c for c in cipher if (c.min_version >= Protocols.TLS13) != is_tls13_or_above]

            if len(mismatch) > 0:
                raise Exception("Cannot combine ciphers for TLS1.3 or above with older ciphers: {}".format([c.name for c in cipher]))

            ciphers.append(self._join_ciphers(cipher))
        else:
            is_tls13_or_above = (cipher.min_version >= Protocols.TLS13)
            ciphers.append(cipher.name)

        if is_tls13_or_above:
            cmdline.append('-ciphersuites')
        else:
            cmdline.append('-cipher')

        return cmdline + ciphers

    @classmethod
    def get_version(cls):
        return cls._version

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        if protocol is Protocols.TLS13:
            if 'openssl-1.1.1' in OpenSSL.get_version():
                return True
            else:
                return False

        return True

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        is_openssl_111 = "openssl-1.1.1" in OpenSSL.get_version()
        if is_openssl_111 and cipher.openssl1_1_1 is False:
            return False

        if not is_openssl_111:
            # OpenSSL 1.0.2 does not have ChaChaPoly
            if 'CHACHA20' in cipher.name:
                return False

        if cipher.fips is False and "fips" in OpenSSL.get_version():
            return False

        if "openssl-1.0.2" in OpenSSL.get_version() and with_curve is not None:
            invalid_ciphers = [
                Ciphers.ECDHE_RSA_AES128_SHA,
                Ciphers.ECDHE_RSA_AES256_SHA,
                Ciphers.ECDHE_RSA_AES128_SHA256,
                Ciphers.ECDHE_RSA_AES256_SHA384,
                Ciphers.ECDHE_RSA_AES128_GCM_SHA256,
                Ciphers.ECDHE_RSA_AES256_GCM_SHA384,
            ]

            # OpenSSL 1.0.2 and 1.0.2-FIPS can't find a shared cipher with S2N
            # when P-384 is used, but I can't find any reason why.
            if with_curve is Curves.P384 and cipher in invalid_ciphers:
                return False

        return True

    def setup_client(self):
        # s_client prints this message before it is ready to send/receive data
        self.ready_to_send_input_marker = 'Verify return code'

        cmd_line = ['openssl', 's_client']
        cmd_line.extend(['-connect', '{}:{}'.format(self.options.host, self.options.port)])

        # Additional debugging that will be captured incase of failure
        cmd_line.extend(['-debug', '-tlsextdebug', '-state'])

        if self.options.key is not None:
            cmd_line.extend(['-key', self.options.key])

        # Unlike s2n, OpenSSL allows us to be much more specific about which TLS
        # protocol to use.
        if self.options.protocol == Protocols.TLS13:
            cmd_line.append('-tls1_3')
        elif self.options.protocol == Protocols.TLS12:
            cmd_line.append('-tls1_2')
        elif self.options.protocol == Protocols.TLS11:
            cmd_line.append('-tls1_1')
        elif self.options.protocol == Protocols.TLS10:
            cmd_line.append('-tls1')

        if self.options.cipher is not None:
            cmd_line.extend(self._cipher_to_cmdline(self.options.cipher))

        if self.options.curve is not None:
            cmd_line.extend(['-curves', str(self.options.curve)])

        if self.options.use_client_auth:
            if self.options.key:
                cmd_line.extend(['-key', self.options.key])
            if self.options.cert:
                cmd_line.extend(['-cert', self.options.cert])

        if self.options.reconnect is True:
            cmd_line.append('-reconnect')

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        if self.options.server_name is not None:
            cmd_line.extend(['-servername', self.options.server_name])
            if self.options.verify_hostname is not None:
                cmd_line.extend(['-verify_hostname', self.options.server_name])

        # Clients are always ready to connect
        self.set_provider_ready()

        return cmd_line

    def setup_server(self):
        # s_server prints this message before it is ready to send/receive data
        self.ready_to_test_marker = 'ACCEPT'

        cmd_line = ['openssl', 's_server']
        cmd_line.extend(['-accept', '{}'.format(self.options.port)])

        if self.options.reconnects_before_exit is not None:
            # If the user request a specific reconnection count, set it here
            cmd_line.extend(['-naccept', str(self.options.reconnects_before_exit)])
        else:
            # Exit after the first connection by default
            cmd_line.extend(['-naccept', '1'])

        # Additional debugging that will be captured incase of failure
        cmd_line.extend(['-debug', '-tlsextdebug', '-state'])

        if self.options.cert is not None:
            cmd_line.extend(['-cert', self.options.cert])
        if self.options.key is not None:
            cmd_line.extend(['-key', self.options.key])

        # Unlike s2n, OpenSSL allows us to be much more specific about which TLS
        # protocol to use.
        if self.options.protocol == Protocols.TLS13:
            cmd_line.append('-tls1_3')
        elif self.options.protocol == Protocols.TLS12:
            cmd_line.append('-tls1_2')
        elif self.options.protocol == Protocols.TLS11:
            cmd_line.append('-tls1_1')
        elif self.options.protocol == Protocols.TLS10:
            cmd_line.append('-tls1')

        if self.options.cipher is not None:
            cmd_line.extend(self._cipher_to_cmdline(self.options.cipher))
            if self.options.cipher.parameters is not None:
                cmd_line.extend(['-dhparam', self.options.cipher.parameters])

        if self.options.curve is not None:
            cmd_line.extend(['-curves', str(self.options.curve)])
        if self.options.use_client_auth is True:
            # We use "Verify" instead of "verify" to require a client cert
            cmd_line.extend(['-Verify', '1'])

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        return cmd_line

class JavaSSL(Provider):
    """
    NOTE: Only a Java SSL client has been set up. The server has not been 
    implemented yet.
    """
    def __init__(self, options: ProviderOptions):
        self.ready_to_send_input_marker = None
        Provider.__init__(self, options)

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        if protocol is Protocols.TLS10:
            return False

        return True

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        # Java SSL does not support CHACHA20 
        if 'CHACHA20' in cipher.name:
            return False

        return True

    def setup_server(self):
        pytest.skip('JavaSSL does not support server mode at this time')

    def setup_client(self):
        self.ready_to_send_input_marker = "Starting handshake"
        cmd_line = ['java', "-classpath", "bin", "SSLSocketClient"]

        if self.options.port is not None:
            cmd_line.extend([self.options.port])

        if self.options.trust_store:
            cmd_line.extend([self.options.trust_store])
        elif self.options.cert:
            cmd_line.extend([self.options.cert])

        if self.options.protocol is not None:
            cmd_line.extend([self.options.protocol.name])

        if self.options.cipher.iana_standard_name is not None:
            cmd_line.extend([self.options.cipher.iana_standard_name])

        # Clients are always ready to connect
        self.set_provider_ready()

        return cmd_line

class BoringSSL(Provider):
    """
    NOTE: In order to focus on the general use of this framework, BoringSSL
    is not yet supported. The client works, the server has not yet been
    implemented, neither are in the default configuration.
    """
    def __init__(self, options: ProviderOptions):
        self.ready_to_send_input_marker = None
        Provider.__init__(self, options)

    def setup_server(self):
        pytest.skip('BoringSSL does not support server mode at this time')

    def setup_client(self):
        self.ready_to_send_input_marker = 'Cert issuer:'
        cmd_line = ['bssl', 's_client']
        cmd_line.extend(['-connect', '{}:{}'.format(self.options.host, self.options.port)])
        if self.options.cert is not None:
            cmd_line.extend(['-cert', self.options.cert])
        if self.options.key is not None:
            cmd_line.extend(['-key', self.options.key])
        if self.options.cipher is not None:
            if self.options.cipher == Ciphersuites.TLS_CHACHA20_POLY1305_SHA256:
                cmd_line.extend(['-cipher', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'])
            elif self.options.cipher == Ciphersuites.TLS_AES_128_GCM_256:
                pytest.skip('BoringSSL does not support Cipher {}'.format(self.options.cipher))
            elif self.options.cipher == Ciphersuites.TLS_AES_256_GCM_384:
                pytest.skip('BoringSSL does not support Cipher {}'.format(self.options.cipher))
        if self.options.curve is not None:
            if self.options.curve == Curves.P256:
                cmd_line.extend(['-curves', 'P-256'])
            elif self.options.curve == Curves.P384:
                cmd_line.extend(['-curves', 'P-384'])
            elif self.options.curve == Curves.P521:
                cmd_line.extend(['-curves', 'P-521'])
            elif self.options.curve == Curves.X25519:
                pytest.skip('BoringSSL does not support curve {}'.format(self.options.curve))

        # Clients are always ready to connect
        self.set_provider_ready()

        return cmd_line


