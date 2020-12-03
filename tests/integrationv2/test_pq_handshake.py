import pytest

from configuration import available_ports, PROVIDERS, PROTOCOLS
from common import Ciphers, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name

CIPHERS = [
    None,  # `None` will default to the appropriate `test_all` cipher preference in the S2N client provider
    Ciphers.KMS_PQ_TLS_1_0_2019_06,
    Ciphers.KMS_PQ_TLS_1_0_2020_02,
    Ciphers.KMS_PQ_TLS_1_0_2020_07,
    Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11,
    Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02,
    Ciphers.KMS_TLS_1_0_2018_10,
]

EXPECTED_RESULTS = {
    # The tuple keys have the form (client_cipher, server_cipher)
    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_PQ_TLS_1_0_2019_06): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r1-Level1"},
    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_PQ_TLS_1_0_2020_02): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r1-Level1"},
    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_PQ_TLS_1_0_2020_07): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r1-Level1"},

    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2019_06): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r1-Level1"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_02): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r2-Level1"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_07): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r2-Level1"},

    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_PQ_TLS_1_0_2019_06): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r1-Level1"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_PQ_TLS_1_0_2020_02): {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r2-Level1"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_PQ_TLS_1_0_2020_07): {"cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384", "kem": "kyber512r2"},

    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, Ciphers.KMS_PQ_TLS_1_0_2019_06): {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp503r1-KEM"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, Ciphers.KMS_PQ_TLS_1_0_2020_02): {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp503r1-KEM"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, Ciphers.KMS_PQ_TLS_1_0_2020_07): {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp503r1-KEM"},

    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2019_06): {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp503r1-KEM"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_02): {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp434r2-KEM"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_07): {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp434r2-KEM"},

    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_TLS_1_0_2018_10): {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_TLS_1_0_2018_10): {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_TLS_1_0_2018_10): {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},

    (Ciphers.KMS_TLS_1_0_2018_10, Ciphers.KMS_PQ_TLS_1_0_2019_06): {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
    (Ciphers.KMS_TLS_1_0_2018_10, Ciphers.KMS_PQ_TLS_1_0_2020_02): {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
    (Ciphers.KMS_TLS_1_0_2018_10, Ciphers.KMS_PQ_TLS_1_0_2020_07): {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
}

"""
Similar to invalid_test_parameters(), this validates the test parameters for
both client and server. Returns True if the test case using these parameters
should be skipped.
"""
def invalid_pq_handshake_test_parameters(*args, **kwargs):
    client_cipher_kwargs = kwargs.copy()
    client_cipher_kwargs["cipher"] = kwargs["client_cipher"]

    server_cipher_kwargs = kwargs.copy()
    server_cipher_kwargs["cipher"] = kwargs["server_cipher"]

    # `or` is correct: invalid_test_parameters() returns True if the parameters are invalid;
    # we want to return True here if either of the sets of parameters are invalid.
    return invalid_test_parameters(*args, **client_cipher_kwargs) or invalid_test_parameters(*args, **server_cipher_kwargs)


@pytest.mark.uncollect_if(func=invalid_pq_handshake_test_parameters)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("client_cipher", CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("server_cipher", CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
def test_pq_handshake(managed_process, protocol, client_cipher, server_cipher, provider):
    host = "localhost"
    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        insecure=True,
        cipher=client_cipher,
        protocol=protocol)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host=host,
        port=port,
        cipher=server_cipher,
        protocol=protocol)

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    expected_result = EXPECTED_RESULTS.get((client_cipher, server_cipher), None)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

        if expected_result is not None:
            assert bytes(expected_result['cipher'].encode('utf-8')) in results.stdout
            assert bytes(expected_result['kem'].encode('utf-8')) in results.stdout

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

        if expected_result is not None:
            assert bytes(expected_result['cipher'].encode('utf-8')) in results.stdout
            assert bytes(expected_result['kem'].encode('utf-8')) in results.stdout

