import copy
import pytest
import subprocess, os

from common import Certificates, Ciphers, Curves, Protocols, AvailablePorts, KemGroups
from configuration import available_ports, PROVIDERS, PROTOCOLS
from common import Ciphers, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import get_expected_s2n_version
from pip._internal.cli.cmdoptions import cert
from constants import TRUST_STORE_BUNDLE

oqs_as_server_test_vectors = [
    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_kemgroup": KemGroups.P256_KYBER512,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_kyber-512-r2"},

    {"client_ciphers": Ciphers.PQ_KYBER_TEST_TLS_1_0_2020_09, "server_kemgroup": KemGroups.P256_KYBER512,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_kyber-512-r2"},

    {"client_ciphers": Ciphers.PQ_BIKE_TEST_TLS_1_0_2020_09, "server_kemgroup": KemGroups.P256_BIKE1L1FO,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_bike-1l1fo-r2"},

    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_09, "server_kemgroup": KemGroups.P256_SIKEP434,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_sike-p434-r2"},

    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_kemgroup": KemGroups.P256_BIKE1L1FO,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_bike-1l1fo-r2"},

    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_kemgroup": KemGroups.P256_SIKEP434,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_sike-p434-r2"},
]

oqs_as_client_test_vectors = [
    {"server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "client_kemgroup": KemGroups.P256_KYBER512,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_kyber-512-r2"},

    {"server_ciphers": Ciphers.PQ_KYBER_TEST_TLS_1_0_2020_09, "client_kemgroup": KemGroups.P256_KYBER512,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_kyber-512-r2"},

    {"server_ciphers": Ciphers.PQ_BIKE_TEST_TLS_1_0_2020_09, "client_kemgroup": KemGroups.P256_BIKE1L1FO,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_bike-1l1fo-r2"},

    {"server_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_09, "client_kemgroup": KemGroups.P256_SIKEP434,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_sike-p434-r2"},

    {"server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "client_kemgroup": KemGroups.P256_BIKE1L1FO,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_bike-1l1fo-r2"},

    {"server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "client_kemgroup": KemGroups.P256_SIKEP434,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_group": "secp256r1_sike-p434-r2"},
]

# May negotiate a KEM group with either p256 or x25519, depending on how s2n was built
pq_s2n_self_talk_test_vectors = [
    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_kyber-512-r2", "x25519_kyber-512-r2"]},

    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_KYBER_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_kyber-512-r2", "x25519_kyber-512-r2"]},

    {"client_ciphers": Ciphers.PQ_KYBER_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_kyber-512-r2", "x25519_kyber-512-r2"]},

    {"client_ciphers": Ciphers.PQ_BIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_bike-1l1fo-r2", "x25519_bike-1l1fo-r2"]},

    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_sike-p434-r2", "x25519_sike-p434-r2"]},

    {"client_ciphers": Ciphers.PQ_KYBER_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_KYBER_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_kyber-512-r2", "x25519_kyber-512-r2"]},

    {"client_ciphers": Ciphers.PQ_BIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_BIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_bike-1l1fo-r2", "x25519_bike-1l1fo-r2"]},

    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_kem_groups": ["secp256r1_sike-p434-r2", "x25519_sike-p434-r2"]},
]

non_pq_s2n_self_talk_test_vectors = [
    # Server will default to non-PQ, ECDHE will be negotiated
    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_ciphers": None,
     "expected_cipher": "TLS_AES_128_GCM_SHA256", "expected_curves": ["secp256r1", "x25519"]},

    # Client will default to non-PQ, ECDHE will be negotiated
    {"client_ciphers": None, "server_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_curves": ["secp256r1", "x25519"]},

    # In these cases, the server will have received a key share for a compatible curve in the ClientHello,
    # but not a compatible KEM group. Even though both client and server support a common PQ group, s2n
    # server prefers to negotiate a group for which it's already received a key share, rather than send HRR.
    # So, ECDHE will be negotiated.
    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_BIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_curves": ["secp256r1", "x25519"]},

    {"client_ciphers": Ciphers.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09, "server_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": "TLS_AES_256_GCM_SHA384", "expected_curves": ["secp256r1", "x25519"]},
]

def get_oqs_openssl_override_env_vars():
    oqs_openssl_install_dir = os.environ["OQS_OPENSSL_1_1_1_INSTALL_DIR"]
    
    override_env_vars = dict()
    override_env_vars["PATH"] = oqs_openssl_install_dir + "/bin"
    override_env_vars["LD_LIBRARY_PATH"] = oqs_openssl_install_dir + "/lib"

    return override_env_vars

@pytest.mark.parametrize("vector", oqs_as_server_test_vectors)
def test_oqs_openssl_as_server(managed_process, vector):
    host = "localhost"
    port = next(available_ports)

    # We are manually passing the cipher flag to s2nc and s2nd.
    # This is because PQ ciphers are specific to S2N at this point
    # in time.
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        insecure=True,
        cipher=vector['client_ciphers'],
        protocol=Protocols.TLS13)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host=host,
        port=port,
        kemgroup=vector['server_kemgroup'],
        protocol=Protocols.TLS13,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key,
        env_overrides=get_oqs_openssl_override_env_vars())

    server = managed_process(OpenSSL, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # OQS OpenSSL is Server, so just check that it had a valid exit code
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(Protocols.TLS13, S2N)

    # Validate S2N Client results were what was expected
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert bytes("Curve: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM Group: {}".format(vector['expected_kem_group']).encode('utf-8')) in results.stdout
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout

@pytest.mark.parametrize("vector", oqs_as_client_test_vectors)
def test_oqs_openssl_as_client(managed_process, vector):
    host = "localhost"
    port = next(available_ports)

    # We are manually passing the cipher flag to s2nc and s2nd.
    # This is because PQ ciphers are specific to S2N at this point
    # in time.
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        kemgroup=vector['client_kemgroup'],
        insecure=True,
        protocol=Protocols.TLS13,
        env_overrides=get_oqs_openssl_override_env_vars())

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host=host,
        port=port,
        cipher=vector['server_ciphers'],
        protocol=Protocols.TLS13,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key)

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    # OQS OpenSSL is Client, so just check that it had a valid exit code
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(Protocols.TLS13, S2N)

    # Validate S2N Server results were what was expected
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert bytes("Curve: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM Group: {}".format(vector['expected_kem_group']).encode('utf-8')) in results.stdout
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout

@pytest.mark.parametrize("vector", pq_s2n_self_talk_test_vectors)
def test_s2n_self_talk(managed_process, vector):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        insecure=True,
        cipher=vector['client_ciphers'],
        protocol=Protocols.TLS13)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host=host,
        port=port,
        cipher=vector['server_ciphers'],
        protocol=Protocols.TLS13,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key)

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    expected_version = get_expected_s2n_version(Protocols.TLS13, S2N)

    kem_group0 = bytes("KEM Group: {}".format(vector["expected_kem_groups"][0]).encode('utf-8'))
    kem_group1 = bytes("KEM Group: {}".format(vector["expected_kem_groups"][1]).encode('utf-8'))

    # Validate S2N Server results were what was expected
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert bytes("Curve: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM: NONE".encode('utf-8')) in results.stdout
        assert (kem_group0 in results.stdout) or (kem_group1 in results.stdout)
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout

    # Validate S2N Client results were what was expected
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert bytes("Curve: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM: NONE".encode('utf-8')) in results.stdout
        assert (kem_group0 in results.stdout) or (kem_group1 in results.stdout)
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout

@pytest.mark.parametrize("vector", non_pq_s2n_self_talk_test_vectors)
def test_non_pq_s2n_self_talk(managed_process, vector):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        insecure=True,
        cipher=vector['client_ciphers'],
        protocol=Protocols.TLS13)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host=host,
        port=port,
        cipher=vector['server_ciphers'],
        protocol=Protocols.TLS13,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key)

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    expected_version = get_expected_s2n_version(Protocols.TLS13, S2N)

    curve0 = bytes("Curve: {}".format(vector["expected_curves"][0]).encode('utf-8'))
    curve1 = bytes("Curve: {}".format(vector["expected_curves"][1]).encode('utf-8'))

    # Validate S2N Server results were what was expected
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert (curve0 in results.stdout) or (curve1 in results.stdout)
        assert bytes("KEM: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM Group: NONE".encode('utf-8')) in results.stdout
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout

    # Validate S2N Client results were what was expected
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert (curve0 in results.stdout) or (curve1 in results.stdout)
        assert bytes("KEM: NONE".encode('utf-8')) in results.stdout
        assert bytes("KEM Group: NONE".encode('utf-8')) in results.stdout
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout
