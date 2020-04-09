##
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

"""
Most s2n integration tests are run against a variety of arguments.
A "scenario" represents a specific set of inputs, such as address,
cipher, version, etc.
"""

import itertools
import multiprocessing
import os
from enum import Enum as BaseEnum
from multiprocessing.pool import ThreadPool

class Enum(BaseEnum):

    def __str__(self):
        return self.name

    @classmethod
    def all(cls):
        return cls


class Version(Enum):
    SSLv3 = 30
    TLS10 = 31
    TLS11 = 32
    TLS12 = 33
    TLS13 = 34


class Mode(Enum):
    client = 0
    server = 1

    def is_client(self):
        return self is Mode.client

    def is_server(self):
        return self is Mode.server

    def other(self):
        return Mode.server if self.is_client() else Mode.client


class Cert():
    def __init__(self, name, prefix, location="../pems/"):
        self.name = name
        self.cert = location + prefix + "_cert.pem"
        self.key = location + prefix + "_key.pem"

    def __str__(self):
        return self.name

ALL_CERTS = [
    Cert("ECDSA_256", "ecdsa_p256_pkcs1"),
    Cert("ECDSA_384", "ecdsa_p384_pkcs1"),
]


class Cipher():
    def __init__(self, name, min_version):
        self.name = name
        self.min_version = min_version

    def valid_for(self, version):
        if not version:
            version = Version.default()

        if version.value < self.min_version.value:
            return False
        if self.min_version is Version.TLS13:
            return version.value >= Version.TLS13.value
        return True

    def __str__(self):
        return self.name

    @classmethod
    def all(cls):
        return ALL_CIPHERS_PER_LIBCRYPTO_VERSION[get_libcrypto()]


def get_libcrypto():
    return str(os.getenv("S2N_LIBCRYPTO")).strip('"')


ALL_CIPHERS = [
    Cipher("TLS_AES_256_GCM_SHA384", Version.TLS13),
    Cipher("TLS_CHACHA20_POLY1305_SHA256", Version.TLS13),
    Cipher("TLS_AES_128_GCM_SHA256", Version.TLS13)
]

# Older versions of Openssl do not support CHACHA20. Current versions of LibreSSL and BoringSSL use a different API
# that is unsupported by s2n.
LEGACY_COMPATIBLE_CIPHERS = list(filter(lambda x: "CHACHA20" not in x.name, ALL_CIPHERS))

ALL_CIPHERS_PER_LIBCRYPTO_VERSION = {
    "openssl-1.1.1"         : ALL_CIPHERS,
    "openssl-1.0.2"         : LEGACY_COMPATIBLE_CIPHERS,
    "openssl-1.0.2-fips"    : LEGACY_COMPATIBLE_CIPHERS,
    "libressl"              : LEGACY_COMPATIBLE_CIPHERS,
    "boringssl"             : LEGACY_COMPATIBLE_CIPHERS,
}

class Curve():
    def __init__(self, name, min_version):
        self.name = name
        self.min_version = min_version

    def valid_for(self, version):
        if not version:
            version = Version.default()

        if version.value < self.min_version.value:
            return False

        return True

    def __str__(self):
        return self.name

    @classmethod
    def all(cls):
        return ALL_CURVES_PER_LIBCRYPTO_VERSION[get_libcrypto()]

ALL_CURVES = [
    Curve("X25519", Version.TLS13),
    Curve("P-256", Version.SSLv3),
    Curve("P-384", Version.SSLv3)
]

# Older versions of Openssl, do not support X25519. Current versions of LibreSSL and BoringSSL use a different API
# that is unsupported by s2n.
LEGACY_COMPATIBLE_CURVES = list(filter(lambda x: "X25519" not in x.name, ALL_CURVES))

ALL_CURVES_PER_LIBCRYPTO_VERSION = {
    "openssl-1.1.1"         : ALL_CURVES,
    "openssl-1.0.2"         : LEGACY_COMPATIBLE_CURVES,
    "openssl-1.0.2-fips"    : LEGACY_COMPATIBLE_CURVES,
    "libressl"              : LEGACY_COMPATIBLE_CURVES,
    "boringssl"             : LEGACY_COMPATIBLE_CURVES,
}


class Scenario:

    """
    Describes the configuration for a specific TLS connection.

    """

    def __init__(self, s2n_mode, host, port, version=None, cipher=None, curve=None,
                 cert=ALL_CERTS[0], s2n_flags=[], peer_flags=[]):
        """
        Args:
            s2n_mode: whether s2n should act as a client or server.
            host: host to connect or listen to.
            port: port to connect or listen to.
            version: which TLS protocol version to use. If None, the implementation will
                use its default.
            cipher: which cipher to use. If None, the implementation will use its default.
            s2n_flags: any extra flags that should be passed to s2n.
            peer_flags: any extra flags that should be passed to the TLS implementation
                that s2n connects to.

        """
        self.s2n_mode = s2n_mode
        self.host = host
        self.port = port
        self.version = version
        self.cipher = cipher
        self.curve = curve
        self.cert = cert
        self.s2n_flags = s2n_flags
        self.peer_flags = peer_flags

    def __str__(self):
        version = self.version if self.version else "DEFAULT"
        cipher = self.cipher if self.cipher else "ANY"
        result = "Mode:%s %s Version:%s Curve:%s Cert:%s Cipher:%s" % \
            (self.s2n_mode, " ".join(self.s2n_flags), str(version).ljust(7), self.curve,
             str(self.cert).ljust(10), str(cipher).ljust(30))

        return result.ljust(100)


def __create_thread_pool():
    threadpool_size = multiprocessing.cpu_count() * 2  # Multiply by 2 since performance improves slightly if CPU has hyperthreading
    threadpool = ThreadPool(processes=threadpool_size)
    return threadpool


def run_scenarios(test_func, scenarios):
    failed = 0
    threadpool = __create_thread_pool()
    results = {}

    print("\tRunning scenarios: " + str(len(scenarios)))

    for scenario in scenarios:
        async_result = threadpool.apply_async(test_func, (scenario,))
        results.update({scenario: async_result})

    threadpool.close()
    threadpool.join()

    results.update((k, v.get()) for k,v in results.items())
    # Sort the results so that failures appear at the end
    sorted_results = sorted(results.items(), key=lambda x: not x[1].is_success())
    for scenario, result in sorted_results:
        print("%s %s" % (str(scenario), str(result).rstrip()))
        if not result.is_success():
            failed += 1

    return failed


def get_scenarios(host, start_port, s2n_modes=Mode.all(), versions=[None], ciphers=[None],
                  curves=Curve.all(), certs=ALL_CERTS, s2n_flags=[], peer_flags=[]):
    port = start_port
    scenarios = []

    combos = itertools.product(versions, s2n_modes, ciphers, curves, certs)
    for (version, s2n_mode, cipher, curve, cert) in combos:
        if cipher and not cipher.valid_for(version):
            continue

        if curve and not curve.valid_for(version):
            continue

        for s2n_mode in s2n_modes:
            scenarios.append(Scenario(
                s2n_mode=s2n_mode,
                host=host,
                port=port,
                version=version,
                cipher=cipher,
                curve=curve,
                cert=cert,
                s2n_flags=s2n_flags,
                peer_flags=peer_flags))
            port += 1
        
    return scenarios

