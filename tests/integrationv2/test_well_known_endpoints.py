import pytest

from constants import TRUST_STORE_BUNDLE
from configuration import available_ports, PROTOCOLS
from common import ProviderOptions, Protocols, Ciphers, pq_enabled
from fixtures import managed_process
from global_flags import get_flag, S2N_FIPS_MODE
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name


ENDPOINTS = [
    "amazon.com",
    "facebook.com",
    "google.com",
    "netflix.com",
    "s3.amazonaws.com",
    "twitter.com",
    "wikipedia.org",
    "yahoo.com",
    "kms.us-east-1.amazonaws.com",
]

CIPHERS = [
    None,  # `None` will default to the appropriate `test_all` cipher preference in the S2N client provider
    Ciphers.KMS_PQ_TLS_1_0_2019_06,
    Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11,
    Ciphers.KMS_PQ_TLS_1_0_2020_07,
    Ciphers.KMS_PQ_TLS_1_0_2020_02,
    Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02
]


if pq_enabled():
    EXPECTED_RESULTS = {
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2019_06):
            {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r1-Level1"},
        ("kms.us-east-1.amazonaws.com", Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11):
            {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp503r1-KEM"},
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2020_07):
            {"cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384", "kem": "kyber512r2"},
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2020_02):
            {"cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384", "kem": "BIKE1r2-Level1"},
        ("kms.us-east-1.amazonaws.com", Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02):
            {"cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384", "kem": "SIKEp434r2-KEM"},
    }
else:
    EXPECTED_RESULTS = {
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2019_06):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
        ("kms.us-east-1.amazonaws.com", Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2020_07):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2020_02):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
        ("kms.us-east-1.amazonaws.com", Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
    }


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("cipher", CIPHERS, ids=get_parameter_name)
def test_well_known_endpoints(managed_process, protocol, endpoint, provider, cipher):
    port = "443"

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=endpoint,
        port=port,
        insecure=False,
        trust_store=TRUST_STORE_BUNDLE,
        protocol=protocol,
        cipher=cipher)

    if get_flag(S2N_FIPS_MODE) is True:
        client_options.trust_store = "../integration/trust-store/ca-bundle.trust.crt"
    else:
        client_options.trust_store = "../integration/trust-store/ca-bundle.crt"

    client = managed_process(provider, client_options, timeout=5)

    expected_result = EXPECTED_RESULTS.get((endpoint, cipher), None)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

        if expected_result is not None:
            assert bytes(expected_result['cipher'].encode('utf-8')) in results.stdout
            assert bytes(expected_result['kem'].encode('utf-8')) in results.stdout
