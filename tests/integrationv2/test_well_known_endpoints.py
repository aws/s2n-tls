import copy
import os
import pytest

from constants import TRUST_STORE_BUNDLE
from configuration import available_ports, PROTOCOLS
from common import ProviderOptions, Protocols, Ciphers
from fixtures import managed_process
from global_flags import get_flag, S2N_NO_PQ, S2N_FIPS_MODE
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name


ENDPOINTS = [
    {"endpoint": "amazon.com"},
    {"endpoint": "facebook.com"},
    {"endpoint": "google.com"},
    {"endpoint": "netflix.com"},
    {"endpoint": "s3.amazonaws.com"},
    {"endpoint": "twitter.com"},
    {"endpoint": "wikipedia.org"},
    {"endpoint": "yahoo.com"},
]


if get_flag(S2N_NO_PQ, False) is False:
    # If PQ was compiled into S2N, test the PQ preferences against KMS
    pq_endpoints = [
        {
            "endpoint": "kms.us-east-1.amazonaws.com",
            "cipher_preference_version": Ciphers.KMS_PQ_TLS_1_0_2019_06,
            "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384",
            "expected_kem": "BIKE1r1-Level1",
        },
        {
            "endpoint": "kms.us-east-1.amazonaws.com",
            "cipher_preference_version": Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11,
            "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384",
            "expected_kem": "SIKEp503r1-KEM",
        },
        {
            "endpoint": "kms.us-east-1.amazonaws.com",
            "cipher_preference_version": Ciphers.KMS_PQ_TLS_1_0_2020_07,
            "expected_cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
            "expected_kem": "kyber512r2",
        },
        {
            "endpoint": "kms.us-east-1.amazonaws.com",
            "cipher_preference_version": Ciphers.KMS_PQ_TLS_1_0_2020_02,
            "expected_cipher": "ECDHE-BIKE-RSA-AES256-GCM-SHA384",
            "expected_kem": "BIKE1r2-Level1",
        },
        {
            "endpoint": "kms.us-east-1.amazonaws.com",
            "cipher_preference_version": Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02,
            "expected_cipher": "ECDHE-SIKE-RSA-AES256-GCM-SHA384",
            "expected_kem": "SIKEp434r2-KEM",
        },
    ]

    ENDPOINTS.extend(pq_endpoints)


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda x: "{}-{}".format(x['endpoint'], x.get('cipher_preference_version', 'Default')))
def test_well_known_endpoints(managed_process, protocol, endpoint):
    port = "443"

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=endpoint['endpoint'],
        port=port,
        insecure=False,
        client_trust_store=TRUST_STORE_BUNDLE,
        protocol=protocol)

    if get_flag(S2N_FIPS_MODE) is True:
        client_options.client_trust_store = "../integration/trust-store/ca-bundle.trust.crt"
    else:
        client_options.client_trust_store = "../integration/trust-store/ca-bundle.crt"

    if 'cipher_preference_version' in endpoint:
        client_options.cipher = endpoint['cipher_preference_version']

    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

        if 'expected_cipher' in endpoint:
            assert bytes(endpoint['expected_cipher'].encode('utf-8')) in results.stdout

        if 'expected_kem' in endpoint:
            assert bytes(endpoint['expected_kem'].encode('utf-8')) in results.stdout
