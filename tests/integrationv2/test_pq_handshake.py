import copy
import pytest

from configuration import available_ports, PROVIDERS, PROTOCOLS
from common import Ciphers, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N
from utils import get_expected_s2n_version


pq_handshake_test_vectors = [
    # The first set of vectors specify client and server cipher preference versions that are compatible for a successful PQ handshake
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r1-Level1"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r1-Level1"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r1-Level1"},

    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r1-Level1"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r2-Level1"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r2-Level1"},

    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r1-Level1"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "expected_kem": "BIKE1r2-Level1"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "expected_cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384", "expected_kem": "kyber512r2"},

    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp503r1-KEM"},
    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp503r1-KEM"},
    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp503r1-KEM"},

    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp503r1-KEM"},
    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp434r2-KEM"},
    {"client_ciphers": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "expected_kem": "SIKEp434r2-KEM"},

    # The last set of vectors specify a "mismatch" between PQ cipher preferences - a classic handshake should be completed
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "server_ciphers": Ciphers.KMS_TLS_1_0_2018_10, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "server_ciphers": Ciphers.KMS_TLS_1_0_2018_10, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "server_ciphers": Ciphers.KMS_TLS_1_0_2018_10, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},

    {"client_ciphers": Ciphers.KMS_TLS_1_0_2018_10, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2019_06, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": Ciphers.KMS_TLS_1_0_2018_10, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_02, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
    {"client_ciphers": Ciphers.KMS_TLS_1_0_2018_10, "server_ciphers": Ciphers.KMS_PQ_TLS_1_0_2020_07, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE"},
]


@pytest.mark.parametrize("vector", pq_handshake_test_vectors)
def test_pq_handshake(managed_process, vector):
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
        cipher=None,
        extra_flags=['--ciphers', vector['client_ciphers'].name],
        protocol=Protocols.TLS12)

    server_options = ProviderOptions(
        mode = Provider.ServerMode,
        host=host,
        port=port,
        cipher=None,
        extra_flags=['--ciphers', vector['server_ciphers'].name],
        protocol=Protocols.TLS12)

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(Protocols.TLS12, S2N)

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert bytes("KEM: {}".format(vector['expected_kem']).encode('utf-8')) in results.stdout
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout

