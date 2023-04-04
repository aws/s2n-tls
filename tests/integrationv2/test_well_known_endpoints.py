import pytest

from constants import TRUST_STORE_BUNDLE, TRUST_STORE_TRUSTED_BUNDLE
from configuration import PROTOCOLS
from common import ProviderOptions, Ciphers, pq_enabled
from fixtures import managed_process  # lgtm [py/unused-import]
from global_flags import get_flag, is_criterion_on, S2N_FIPS_MODE, S2N_USE_CRITERION
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name, to_bytes


ENDPOINTS = [
    "www.akamai.com",
    "www.amazon.com",
    "kms.us-east-1.amazonaws.com",
    "s3.us-west-2.amazonaws.com",
    "www.apple.com",
    "www.att.com",
    #    "www.badssl.com",
    #    "mozilla-intermediate.badssl.com",
    #    "mozilla-modern.badssl.com",
    #    "rsa2048.badssl.com",
    #    "rsa4096.badssl.com",
    #    "sha256.badssl.com",
    #    "sha384.badssl.com",
    #    "sha512.badssl.com",
    #    "tls-v1-0.badssl.com",
    #    "tls-v1-1.badssl.com",
    #    "tls-v1-2.badssl.com",
    "www.cloudflare.com",
    "www.ebay.com",
    "www.f5.com",
    "www.facebook.com",
    "www.google.com",
    "www.github.com",
    "www.ibm.com",
    "www.microsoft.com",
    "www.mozilla.org",
    "www.netflix.com",
    "www.openssl.org",
    "www.samsung.com",
    "www.t-mobile.com",
    "www.twitter.com",
    "www.verizon.com",
    "www.wikipedia.org",
    "www.yahoo.com",
    "www.youtube.com",
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
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
        ("kms.us-east-1.amazonaws.com", Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2020_07):
            {"cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384", "kem": "kyber512r3"},
        ("kms.us-east-1.amazonaws.com", Ciphers.KMS_PQ_TLS_1_0_2020_02):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
        ("kms.us-east-1.amazonaws.com", Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02):
            {"cipher": "ECDHE-RSA-AES256-GCM-SHA384", "kem": "NONE"},
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
@pytest.mark.flaky(reruns=5, reruns_delay=4)
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
        client_options.trust_store = TRUST_STORE_TRUSTED_BUNDLE

    # TODO: Understand the failure with criterion and this endpoint.
    if is_criterion_on() and 'www.netflix.com' in endpoint:
        pytest.skip()

    # expect_stderr=True because S2N sometimes receives OCSP responses:
    # https://github.com/aws/s2n-tls/blob/14ed186a13c1ffae7fbb036ed5d2849ce7c17403/bin/echo.c#L180-L184
    client = managed_process(provider, client_options,
                             timeout=5, expect_stderr=True)

    expected_result = EXPECTED_RESULTS.get((endpoint, cipher), None)

    for results in client.get_results():
        results.assert_success()

        if expected_result is not None:
            assert to_bytes(expected_result['cipher']) in results.stdout
            assert to_bytes(expected_result['kem']) in results.stdout
