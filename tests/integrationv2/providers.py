import os
import subprocess
import pytest
import threading

from common import ProviderOptions, Ciphers, Curves, Protocols, Signatures
from global_flags import get_flag, S2N_PROVIDER_VERSION, S2N_FIPS_MODE
from global_flags import S2N_USE_CRITERION
from stat import S_IMODE


class Provider(object):
    """
    A provider defines a specific provider of TLS. This could be
    S2N, OpenSSL, BoringSSL, etc.
    """

    ClientMode = "client"
    ServerMode = "server"

    def __init__(self, options: ProviderOptions):
        # If the provider includes stderr output on a success, set this to True.
        self.expect_stderr = False

        # If the test should wait for a specific output message before beginning,
        # put that message in ready_to_test_marker
        self.ready_to_test_marker = None

        # If a newline character should be added to messages being sent. Required
        # with some providers to properly write to stdin.
        self.send_with_newline = False

        # By default, we expect clients to send, but not servers.
        if options.mode == Provider.ClientMode:
            self.ready_to_send_input_marker = self.get_send_marker()
        else:
            self.ready_to_send_input_marker = None

        # Allows users to determine if the provider is ready to begin testing
        self._provider_ready_condition = threading.Condition()
        self._provider_ready = False

        if type(options) is not ProviderOptions:
            raise TypeError

        self.options = options
        if self.options.mode == Provider.ServerMode:
            self.cmd_line = self.setup_server()  # lgtm [py/init-calls-subclass]
        elif self.options.mode == Provider.ClientMode:
            self.cmd_line = self.setup_client()  # lgtm [py/init-calls-subclass]

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
    def get_send_marker(cls):
        """
        This should be the last message printed before the client/server can send data.
        """
        return None

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        raise NotImplementedError

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        raise NotImplementedError

    @classmethod
    def supports_signature(cls, signature):
        return True

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
        Provider.__init__(self, options)

        self.send_with_newline = True  # lgtm [py/overwritten-inherited-attribute]

    @classmethod
    def get_send_marker(cls):
        return 's2n is ready'

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        # TLS 1.3 is unsupported for openssl-1.0
        # libressl and boringssl are disabled because of configuration issues
        # see https://github.com/aws/s2n-tls/issues/3250
        TLS_13_UNSUPPORTED_LIBCRYPTOS = {
            "libressl",
            "boringssl",
            "openssl-1.0"
        }

        # Disable TLS 1.3 tests for all libcryptos that don't support 1.3
        if protocol == Protocols.TLS13:
            current_libcrypto = get_flag(S2N_PROVIDER_VERSION)
            for unsupported_lc in TLS_13_UNSUPPORTED_LIBCRYPTOS:
                # e.g. "openssl-1.0" in "openssl-1.0.2-fips"
                if unsupported_lc in current_libcrypto:
                    return False

        # SSLv3 cannot be negotiated in FIPS mode with libcryptos other than AWS-LC.
        if all([
            protocol == Protocols.SSLv3,
            get_flag(S2N_FIPS_MODE),
            "awslc" not in get_flag(S2N_PROVIDER_VERSION)
        ]):
            return False

        return True

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        # Disable chacha20 and RC4 tests in libcryptos that don't support those
        # algorithms
        unsupported_configurations = {
            "CHACHA20": ["openssl-1.0.2", "libressl"],
            "RC4": ["openssl-3"],
        }

        for unsupported_cipher, unsupported_libcryptos in unsupported_configurations.items():
            # the queried cipher has some libcrypto's that don't support it
            # e.g. "RC4" in "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
            if unsupported_cipher in cipher.name:
                current_libcrypto = get_flag(S2N_PROVIDER_VERSION)
                for lc in unsupported_libcryptos:
                    # e.g. "openssl-3" in "openssl-3.0.7"
                    if lc in current_libcrypto:
                        return False
        return True

    @classmethod
    def supports_signature(cls, signature):
        # Disable RSA_PSS_RSAE_SHA256 in unsupported libcryptos
        if any([
            libcrypto in get_flag(S2N_PROVIDER_VERSION)
            for libcrypto in [
                "openssl-1.0.2",
                "libressl",
                "boringssl"
            ]
        ]) and signature == Signatures.RSA_PSS_RSAE_SHA256:
            return False

        return True

    def setup_client(self):
        """
        Using the passed ProviderOptions, create a command line.
        """
        cmd_line = []
        if self.options.use_mainline_version is True:
            cmd_line.append('s2nc_head')
        else:
            cmd_line.append('s2nc')
        cmd_line.append('--non-blocking')

        # Tests requiring reconnects can't wait on echo data,
        # but all other tests can.
        if self.options.reconnect is not True:
            cmd_line.append('-e')

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

        if get_flag(S2N_FIPS_MODE):
            cmd_line.append("--enter-fips-mode")

        if self.options.enable_client_ocsp:
            cmd_line.extend(["--status"])

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        cmd_line.extend([self.options.host, self.options.port])

        # Clients are always ready to connect
        self.set_provider_ready()

        return cmd_line

    def setup_server(self):
        # s2nd prints this message after it begins listening for connections
        self.ready_to_test_marker = 'Listening on'

        """
        Using the passed ProviderOptions, create a command line.
        """
        cmd_line = []
        if self.options.use_mainline_version is True:
            cmd_line.append('s2nd_head')
        else:
            cmd_line.append('s2nd')
        cmd_line.extend(['-X', '--self-service-blinding', '--non-blocking'])

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
            cmd_line.append(
                '--max-conns={}'.format(self.options.reconnects_before_exit))

        if get_flag(S2N_FIPS_MODE):
            cmd_line.append("--enter-fips-mode")

        if self.options.ocsp_response is not None:
            cmd_line.extend(["--ocsp", self.options.ocsp_response])

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        cmd_line.extend([self.options.host, self.options.port])

        return cmd_line


class CriterionS2N(S2N):
    """
    Wrap the S2N provider in criterion-rust
    The CriterionS2N provider modifies the test command being run by pytest to be the criterion benchmark binary
    and moves the s2nc/d command line arguments into an environment variable.  The binary created by
    `cargo bench --no-run` has a unique name and must be searched for, which the CriterionS2N provider finds
    and replaces in the final testing command. The arguments to s2nc/d are moved to the environment variables
    `S2NC_ARGS` or `S2ND_ARGS`, along with the test name, which are read by the rust benchmark when spawning
    s2nc/d as subprocesses.
    """
    criterion_off = 'off'
    criterion_delta = 'delta'
    criterion_baseline = 'baseline'
    # Figure out what mode to run in: baseline or delta
    criterion_mode = get_flag(S2N_USE_CRITERION)

    def _find_s2n_benchmark(self, pattern):
        # Use executable bit to find the correct file.
        result = find_files(pattern, root_dir=self.cargo_root, modes=['0o775', '0o755'])
        if len(result) != 1:
            raise FileNotFoundError(
                f"Exactly one s2n criterion benchmark not found. Found {result}.")
        else:
            return result[0]

    def _find_cargo(self):
        return os.path.abspath("../../bindings/rust")

    def _cargo_bench(self):
        """
        Find the handlers
        """
        self.s2nc_bench = self._find_s2n_benchmark("s2nc-")
        self.s2nd_bench = self._find_s2n_benchmark("s2nd-")

    def __init__(self, options: ProviderOptions):
        super().__init__(options)
        # Set cargo root
        self.cargo_root = self._find_cargo()

        # Find the criterion binaries
        self._cargo_bench()

        # strip off the s2nc/d at the front because criterion
        if 's2nc' in self.cmd_line[0] or 's2nd' in self.cmd_line[0]:
            self.cmd_line = self.cmd_line[1:]

        # strip off the s2nc -e argument, criterion handler isn't sending any STDIN characters,
        # and makes it look like s2nc is hanging.
        # WARNING: this is a blocker for any test that requires STDIN.
        if '-e' in self.cmd_line:
            self.cmd_line.remove('-e')
            print(f"***** cmd_line is now {self.cmd_line}")

        # Copy the command arguments to an environment variable for the harness to read.
        if self.options.mode == Provider.ServerMode:
            self.options.env_overrides.update(
                {'S2ND_ARGS': ' '.join(self.cmd_line),
                 'S2ND_TEST_NAME': f"{self.options.cipher}_{self.options.host}"})
            self.capture_server_args()
        elif self.options.mode == Provider.ClientMode:
            self.options.env_overrides.update(
                {'S2NC_ARGS': ' '.join(self.cmd_line),
                 'S2NC_TEST_NAME': f"{self.options.cipher}_{self.options.host}"})
            if self.criterion_mode == CriterionS2N.criterion_baseline:
                self.capture_client_args_baseline()
            if self.criterion_mode == CriterionS2N.criterion_delta:
                self.capture_client_args_delta()

    def capture_server_args(self):
        self.cmd_line = [self.s2nd_bench, "--bench",
                         "s2nd", "--save-baseline", "main"]

    # Saves baseline data with the tag "main"
    # see https://bheisler.github.io/criterion.rs/book/user_guide/command_line_options.html
    def capture_client_args_baseline(self):
        self.cmd_line = [self.s2nc_bench, "--bench",
                         "s2nc", "--save-baseline", "main"]

    # "By default, Criterion.rs will compare the measurements against the previous run"
    # This run is stored with the tag "new"
    # https://bheisler.github.io/criterion.rs/book/user_guide/command_line_options.html
    def capture_client_args_delta(self):
        self.cmd_line = [self.s2nc_bench, "--bench", "s2nc", "--plotting-backend", "plotters", "--baseline", "main"]


class OpenSSL(Provider):
    _version = get_flag(S2N_PROVIDER_VERSION)

    def __init__(self, options: ProviderOptions):
        Provider.__init__(self, options)
        # We print some OpenSSL logging that includes stderr
        self.expect_stderr = True  # lgtm [py/overwritten-inherited-attribute]
        # Current provider needs 1.1.x https://github.com/aws/s2n-tls/issues/3963
        self._is_openssl_11()

    @classmethod
    def get_send_marker(cls):
        return 'Verify return code'

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
            mismatch = [c for c in cipher if (
                c.min_version >= Protocols.TLS13) != is_tls13_or_above]

            if len(mismatch) > 0:
                raise Exception("Cannot combine ciphers for TLS1.3 or above with older ciphers: {}".format(
                    [c.name for c in cipher]))

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
        if protocol is Protocols.SSLv3:
            return False

        return True

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        return True

    def _is_openssl_11(self) -> None:
        result = subprocess.run(["openssl", "version"], shell=False, capture_output=True, text=True)
        version_str = result.stdout.split(" ")
        project = version_str[0]
        version = version_str[1]
        print(f"openssl version: {project} version: {version}")
        if (project != "OpenSSL" or version[0:3] != "1.1"):
            raise FileNotFoundError(f"Openssl version returned {version}, expected 1.1.x.")

    def setup_client(self):
        cmd_line = ['openssl', 's_client']
        cmd_line.extend(
            ['-connect', '{}:{}'.format(self.options.host, self.options.port)])

        # Additional debugging that will be captured incase of failure
        if self.options.verbose:
            cmd_line.append('-debug')

        cmd_line.extend(['-tlsextdebug', '-state'])

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
        elif self.options.protocol == Protocols.SSLv3:
            cmd_line.append('-ssl3')

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

        if self.options.enable_client_ocsp:
            cmd_line.append("-status")

        if self.options.signature_algorithm is not None:
            cmd_line.extend(
                ["-sigalgs", self.options.signature_algorithm.name])

        if self.options.record_size is not None:
            cmd_line.extend(["-max_send_frag", str(self.options.record_size)])

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
            cmd_line.extend(
                ['-naccept', str(self.options.reconnects_before_exit)])
        else:
            # Exit after the first connection by default
            cmd_line.extend(['-naccept', '1'])

        # Additional debugging that will be captured incase of failure
        if self.options.verbose:
            cmd_line.append('-debug')

        cmd_line.extend(['-tlsextdebug', '-state'])

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
        elif self.options.protocol == Protocols.SSLv3:
            cmd_line.append('-ssl3')

        if self.options.cipher is not None:
            cmd_line.extend(self._cipher_to_cmdline(self.options.cipher))
            if self.options.cipher.parameters is not None:
                cmd_line.extend(['-dhparam', self.options.cipher.parameters])

        if self.options.curve is not None:
            cmd_line.extend(['-curves', str(self.options.curve)])
        if self.options.use_client_auth is True:
            # We use "Verify" instead of "verify" to require a client cert
            cmd_line.extend(['-Verify', '1'])

        if self.options.ocsp_response is not None:
            cmd_line.extend(["-status_file", self.options.ocsp_response])

        if self.options.signature_algorithm is not None:
            cmd_line.extend(
                ["-sigalgs", self.options.signature_algorithm.name])

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        return cmd_line


class SSLv3Provider(OpenSSL):
    def __init__(self, options: ProviderOptions):
        OpenSSL.__init__(self, options)
        self._override_libssl(options)

    def _override_libssl(self, options: ProviderOptions):
        install_dir = os.environ["OPENSSL_1_0_2_INSTALL_DIR"]

        override_env_vars = dict()
        override_env_vars["PATH"] = install_dir + "/bin"
        override_env_vars["LD_LIBRARY_PATH"] = install_dir + "/lib"
        options.env_overrides = override_env_vars

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        if protocol is Protocols.SSLv3:
            return True
        return False


class JavaSSL(Provider):
    """
    NOTE: Only a Java SSL client has been set up. The server has not been
    implemented yet.
    """

    def __init__(self, options: ProviderOptions):
        Provider.__init__(self, options)

    @classmethod
    def get_send_marker(cls):
        return "Starting handshake"

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        # https://aws.amazon.com/blogs/opensource/tls-1-0-1-1-changes-in-openjdk-and-amazon-corretto/
        if protocol is Protocols.SSLv3 or protocol is Protocols.TLS10 or protocol is Protocols.TLS11:
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
        Provider.__init__(self, options)

    @classmethod
    def get_send_marker(cls):
        return 'Cert issuer:'

    def setup_server(self):
        cmd_line = ['bssl', 's_server']
        cmd_line.extend(['-accept', self.options.port])
        if self.options.cert is not None:
            cmd_line.extend(['-cert', self.options.cert])
        if self.options.key is not None:
            cmd_line.extend(['-key', self.options.key])
        if self.options.curve is not None:
            if self.options.curve == Curves.P256:
                cmd_line.extend(['-curves', 'P-256'])
            elif self.options.curve == Curves.P384:
                cmd_line.extend(['-curves', 'P-384'])
            elif self.options.curve == Curves.P521:
                cmd_line.extend(['-curves', 'P-521'])
            elif self.options.curve == Curves.SecP256r1Kyber768Draft00:
                cmd_line.extend(['-curves', 'SecP256r1Kyber768Draft00'])
            elif self.options.curve == Curves.X25519Kyber768Draft00:
                cmd_line.extend(['-curves', 'X25519Kyber768Draft00'])
            elif self.options.curve == Curves.X25519:
                pytest.skip('BoringSSL does not support curve {}'.format(
                    self.options.curve))

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        return cmd_line

    def setup_client(self):
        cmd_line = ['bssl', 's_client']
        cmd_line.extend(
            ['-connect', '{}:{}'.format(self.options.host, self.options.port)])
        if self.options.cert is not None:
            cmd_line.extend(['-cert', self.options.cert])
        if self.options.key is not None:
            cmd_line.extend(['-key', self.options.key])
        if self.options.cipher is not None:
            if self.options.cipher == Ciphersuites.TLS_CHACHA20_POLY1305_SHA256:
                cmd_line.extend(
                    ['-cipher', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'])
            elif self.options.cipher == Ciphersuites.TLS_AES_128_GCM_256:
                pytest.skip('BoringSSL does not support Cipher {}'.format(
                    self.options.cipher))
            elif self.options.cipher == Ciphersuites.TLS_AES_256_GCM_384:
                pytest.skip('BoringSSL does not support Cipher {}'.format(
                    self.options.cipher))
        if self.options.curve is not None:
            if self.options.curve == Curves.P256:
                cmd_line.extend(['-curves', 'P-256'])
            elif self.options.curve == Curves.P384:
                cmd_line.extend(['-curves', 'P-384'])
            elif self.options.curve == Curves.P521:
                cmd_line.extend(['-curves', 'P-521'])
            elif self.options.curve == Curves.SecP256r1Kyber768Draft00:
                cmd_line.extend(['-curves', 'SecP256r1Kyber768Draft00'])
            elif self.options.curve == Curves.X25519Kyber768Draft00:
                cmd_line.extend(['-curves', 'X25519Kyber768Draft00'])
            elif self.options.curve == Curves.X25519:
                pytest.skip('BoringSSL does not support curve {}'.format(
                    self.options.curve))

        if self.options.extra_flags is not None:
            cmd_line.extend(self.options.extra_flags)

        # Clients are always ready to connect
        self.set_provider_ready()

        return cmd_line


class GnuTLS(Provider):
    def __init__(self, options: ProviderOptions):
        Provider.__init__(self, options)

        self.expect_stderr = True  # lgtm [py/overwritten-inherited-attribute]
        self.send_with_newline = True  # lgtm [py/overwritten-inherited-attribute]

    @staticmethod
    def cipher_to_priority_str(cipher):
        return {
            Ciphers.DHE_RSA_AES128_SHA:         "DHE-RSA:+AES-128-CBC:+SHA1",
            Ciphers.DHE_RSA_AES256_SHA:         "DHE-RSA:+AES-256-CBC:+SHA1",
            Ciphers.DHE_RSA_AES128_SHA256:      "DHE-RSA:+AES-128-CBC:+SHA256",
            Ciphers.DHE_RSA_AES256_SHA256:      "DHE-RSA:+AES-256-CBC:+SHA256",
            Ciphers.DHE_RSA_AES128_GCM_SHA256:  "DHE-RSA:+AES-128-GCM:+AEAD",
            Ciphers.DHE_RSA_AES256_GCM_SHA384:  "DHE-RSA:+AES-256-GCM:+AEAD",
            Ciphers.DHE_RSA_CHACHA20_POLY1305:  "DHE-RSA:+CHACHA20-POLY1305:+AEAD",

            Ciphers.AES128_SHA:         "RSA:+AES-128-CBC:+SHA1",
            Ciphers.AES256_SHA:         "RSA:+AES-256-CBC:+SHA1",
            Ciphers.AES128_SHA256:      "RSA:+AES-128-CBC:+SHA256",
            Ciphers.AES256_SHA256:      "RSA:+AES-256-CBC:+SHA256",
            Ciphers.AES128_GCM_SHA256:  "RSA:+AES-128-GCM:+AEAD",
            Ciphers.AES256_GCM_SHA384:  "RSA:+AES-256-GCM:+AEAD",

            Ciphers.ECDHE_ECDSA_AES128_SHA:         "ECDHE-ECDSA:+AES-128-CBC:+SHA1",
            Ciphers.ECDHE_ECDSA_AES256_SHA:         "ECDHE-ECDSA:+AES-256-CBC:+SHA1",
            Ciphers.ECDHE_ECDSA_AES128_SHA256:      "ECDHE-ECDSA:+AES-128-CBC:+SHA256",
            Ciphers.ECDHE_ECDSA_AES256_SHA384:      "ECDHE-ECDSA:+AES-256-CBC:+SHA384",
            Ciphers.ECDHE_ECDSA_AES128_GCM_SHA256:  "ECDHE-ECDSA:+AES-128-GCM:+AEAD",
            Ciphers.ECDHE_ECDSA_AES256_GCM_SHA384:  "ECDHE-ECDSA:+AES-256-GCM:+AEAD",

            Ciphers.ECDHE_RSA_AES128_SHA:           "ECDHE-RSA:+AES-128-CBC:+SHA1",
            Ciphers.ECDHE_RSA_AES256_SHA:           "ECDHE-RSA:+AES-256-CBC:+SHA1",
            Ciphers.ECDHE_RSA_AES128_SHA256:        "ECDHE-RSA:+AES-128-CBC:+SHA256",
            Ciphers.ECDHE_RSA_AES256_SHA384:        "ECDHE-RSA:+AES-256-CBC:+SHA384",
            Ciphers.ECDHE_RSA_AES128_GCM_SHA256:    "ECDHE-RSA:+AES-128-GCM:+AEAD",
            Ciphers.ECDHE_RSA_AES256_GCM_SHA384:    "ECDHE-RSA:+AES-256-GCM:+AEAD",
            Ciphers.ECDHE_RSA_CHACHA20_POLY1305:    "ECDHE-RSA:+CHACHA20-POLY1305:+AEAD"
        }.get(cipher)

    @staticmethod
    def protocol_to_priority_str(protocol):
        if not protocol:
            return None
        return {
            Protocols.TLS10.value: "VERS-TLS1.0",
            Protocols.TLS11.value: "VERS-TLS1.1",
            Protocols.TLS12.value: "VERS-TLS1.2",
            Protocols.TLS13.value: "VERS-TLS1.3"
        }.get(protocol.value)

    @staticmethod
    def curve_to_priority_str(curve):
        return {
            Curves.P256:    "CURVE-SECP256R1",
            Curves.P384:    "CURVE-SECP384R1",
            Curves.P521:    "CURVE-SECP521R1",
            Curves.X25519:  "CURVE-X25519"
        }.get(curve)

    @staticmethod
    def sigalg_to_priority_str(sigalg):
        return {
            Signatures.RSA_SHA1:    "SIGN-RSA-SHA1",
            Signatures.RSA_SHA256:  "SIGN-RSA-SHA256",
            Signatures.RSA_SHA384:  "SIGN-RSA-SHA384",
            Signatures.RSA_SHA512:  "SIGN-RSA-SHA512",
        }.get(sigalg)

    @classmethod
    def get_send_marker(cls):
        return "Simple Client Mode:"

    def create_priority_str(self):
        priority_str = "NONE"

        protocol_to_priority_str = self.protocol_to_priority_str(self.options.protocol)
        if protocol_to_priority_str:
            priority_str += ":+" + protocol_to_priority_str
        else:
            priority_str += ":+VERS-ALL"

        cipher_to_priority_str = self.cipher_to_priority_str(self.options.cipher)
        if cipher_to_priority_str:
            priority_str += ":+" + cipher_to_priority_str
        else:
            priority_str += ":+KX-ALL:+CIPHER-ALL:+MAC-ALL"

        curve_to_priority_str = self.curve_to_priority_str(self.options.curve)
        if curve_to_priority_str:
            priority_str += ":+" + curve_to_priority_str
        else:
            priority_str += ":+GROUP-ALL"

        sigalg_to_priority_str = self.sigalg_to_priority_str(self.options.signature_algorithm)
        if sigalg_to_priority_str:
            priority_str += ":+" + sigalg_to_priority_str
        else:
            priority_str += ":+SIGN-ALL"

        priority_str += ":+COMP-NULL"

        # A digital signature option is not included for the test RSA certs, so GnuTLS must be
        # told to use these certs regardless. The %COMPAT priority string option enables this for
        # client certificates, and the undocumented %DEBUG_ALLOW_KEY_USAGE_VIOLATIONS priority
        # string option enables this for server certificates.
        priority_str += ":%COMPAT"
        priority_str += ":%DEBUG_ALLOW_KEY_USAGE_VIOLATIONS"

        return priority_str

    def setup_client(self):
        self.set_provider_ready()

        cmd_line = [
            "gnutls-cli",
            "--port", str(self.options.port),
            self.options.host,
            "--debug", "9999"
        ]

        if self.options.verbose:
            cmd_line.append("--verbose")

        if self.options.cert and self.options.key:
            cmd_line.extend(["--x509certfile", self.options.cert])
            cmd_line.extend(["--x509keyfile", self.options.key])

        priority_str = self.create_priority_str()
        cmd_line.extend(["--priority", priority_str])

        if self.options.insecure:
            cmd_line.extend(["--insecure"])

        if self.options.enable_client_ocsp:
            cmd_line.append("--ocsp")

        if self.options.record_size:
            cmd_line.extend(["--recordsize", str(self.options.record_size)])

        if self.options.extra_flags:
            cmd_line.extend(self.options.extra_flags)

        return cmd_line

    def setup_server(self):
        self.ready_to_test_marker = "Echo Server listening on"

        cmd_line = [
            "gnutls-serv",
            f"--port={self.options.port}",
            "--echo",
            "--debug=9999"
        ]

        if self.options.cert is not None:
            cmd_line.extend(["--x509certfile", self.options.cert])
        if self.options.key is not None:
            cmd_line.extend(["--x509keyfile", self.options.key])

        priority_str = self.create_priority_str()
        cmd_line.extend(["--priority", priority_str])

        if self.options.cipher:
            if self.options.cipher.parameters:
                cmd_line.extend(["--dhparams", self.options.cipher.parameters])

        if self.options.ocsp_response:
            cmd_line.extend(["--ocsp-response", self.options.ocsp_response])

        if self.options.use_client_auth:
            cmd_line.append("--require-client-cert")

        if self.options.extra_flags:
            cmd_line.extend(self.options.extra_flags)

        return cmd_line

    @classmethod
    def supports_protocol(cls, protocol, with_cert=None):
        return GnuTLS.protocol_to_priority_str(protocol) is not None

    @classmethod
    def supports_cipher(cls, cipher, with_curve=None):
        return GnuTLS.cipher_to_priority_str(cipher) is not None

    @classmethod
    def supports_signature(cls, signature):
        return GnuTLS.sigalg_to_priority_str(signature) is not None


def find_files(file_glob, root_dir=".", modes=[]):
    """
    find util in python form.
    file_glob: a snippet of the filename, e.g. ".py"
    root_dir: starting point for search
    mode is an octal representation of owner/group/other, e.g.: '0o644'
    """
    result = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file_glob in file:
                full_name = os.path.abspath(os.path.join(root, file))
                if len(modes) != 0:
                    try:
                        stat = oct(S_IMODE(os.stat(full_name).st_mode))
                        if stat in modes:
                            result.append(full_name)
                    except FileNotFoundError:
                        # symlinks
                        pass
                else:
                    result.append(full_name)

    return result
