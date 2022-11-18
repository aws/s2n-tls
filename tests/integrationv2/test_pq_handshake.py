import pytest
import os

from configuration import available_ports 
from common import Ciphers, ProviderOptions, Protocols, KemGroups, Certificates, pq_enabled
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, to_bytes
from global_flags import get_flag, S2N_PROVIDER_VERSION 

CIPHERS = [
    None,  # `None` will default to the appropriate `test_all` cipher preference in the S2N client provider
    Ciphers.KMS_PQ_TLS_1_0_2019_06,
    Ciphers.KMS_PQ_TLS_1_0_2020_02,
    Ciphers.KMS_PQ_TLS_1_0_2020_07,
    Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11,
    Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02,
    Ciphers.KMS_TLS_1_0_2018_10,
    Ciphers.PQ_TLS_1_0_2020_12,
]

KEM_GROUPS = [
    KemGroups.P256_KYBER512R3,
]

EXPECTED_RESULTS = {
    # The tuple keys have the form (client_{cipher, kem_group}, server_{cipher, kem_group})
    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_PQ_TLS_1_0_2019_06):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_PQ_TLS_1_0_2020_02):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_PQ_TLS_1_0_2020_07):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},

    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2019_06):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_02):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_07):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},

    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_PQ_TLS_1_0_2019_06):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_PQ_TLS_1_0_2020_02):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_PQ_TLS_1_0_2020_07):
        {"cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
            "kem": "kyber512r3", "kem_group": "NONE"},

    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, Ciphers.KMS_PQ_TLS_1_0_2019_06):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, Ciphers.KMS_PQ_TLS_1_0_2020_02):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2019_11, Ciphers.KMS_PQ_TLS_1_0_2020_07):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},

    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2019_06):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_02):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.PQ_SIKE_TEST_TLS_1_0_2020_02, Ciphers.KMS_PQ_TLS_1_0_2020_07):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},

    (Ciphers.KMS_PQ_TLS_1_0_2019_06, Ciphers.KMS_TLS_1_0_2018_10):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_02, Ciphers.KMS_TLS_1_0_2018_10):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.KMS_TLS_1_0_2018_10):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},

    (Ciphers.KMS_TLS_1_0_2018_10, Ciphers.KMS_PQ_TLS_1_0_2019_06):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_TLS_1_0_2018_10, Ciphers.KMS_PQ_TLS_1_0_2020_02):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},
    (Ciphers.KMS_TLS_1_0_2018_10, Ciphers.KMS_PQ_TLS_1_0_2020_07):
        {"cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "kem": "NONE", "kem_group": "NONE"},

    # The expected kem_group string for this case purposefully excludes a curve;
    # depending on how s2n was compiled, the curve may be either x25519 or p256.
    (Ciphers.PQ_TLS_1_0_2020_12, Ciphers.PQ_TLS_1_0_2020_12):
        {"cipher": "TLS_AES_256_GCM_SHA384",
            "kem": "NONE", "kem_group": "_kyber-512-r3"},
    (Ciphers.PQ_TLS_1_0_2020_12, Ciphers.KMS_PQ_TLS_1_0_2020_07):
        {"cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
            "kem": "kyber512r3", "kem_group": "NONE"},
    (Ciphers.KMS_PQ_TLS_1_0_2020_07, Ciphers.PQ_TLS_1_0_2020_12):
        {"cipher": "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
            "kem": "kyber512r3", "kem_group": "NONE"},
    (Ciphers.PQ_TLS_1_0_2020_12, KemGroups.P256_KYBER512R3):
        {"cipher": "AES256_GCM_SHA384", "kem": "NONE",
            "kem_group": "secp256r1_kyber-512-r3"},
    (KemGroups.P256_KYBER512R3, Ciphers.PQ_TLS_1_0_2020_12):
        {"cipher": "AES256_GCM_SHA384", "kem": "NONE",
            "kem_group": "secp256r1_kyber-512-r3"},
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


def get_oqs_openssl_override_env_vars():
    oqs_openssl_install_dir = os.environ["OQS_OPENSSL_1_1_1_INSTALL_DIR"]

    override_env_vars = dict()
    override_env_vars["PATH"] = oqs_openssl_install_dir + "/bin"
    override_env_vars["LD_LIBRARY_PATH"] = oqs_openssl_install_dir + "/lib"

    return override_env_vars


def assert_s2n_negotiation_parameters(s2n_results, expected_result):
    if expected_result is not None:
        assert to_bytes(
            ("Cipher negotiated: " + expected_result['cipher'])) in s2n_results.stdout
        assert to_bytes(
            ("KEM: " + expected_result['kem'])) in s2n_results.stdout
        # Purposefully leave off the "KEM Group: " prefix in order to perform partial matches
        # without specifying the curve.
        assert to_bytes(expected_result['kem_group']) in s2n_results.stdout


def test_nothing():
    """
    Sometimes the pq handshake test parameters in combination with the s2n libcrypto
    results in no test cases existing. In this case, pass a nothing test to avoid
    marking the entire codebuild run as failed.
    """
    assert True


@pytest.mark.uncollect_if(func=invalid_pq_handshake_test_parameters)
@pytest.mark.parametrize("protocol", [Protocols.TLS12, Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", [Certificates.RSA_4096_SHA512], ids=get_parameter_name)
@pytest.mark.parametrize("client_cipher", CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("server_cipher", CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2nc_to_s2nd_pq_handshake(managed_process, protocol, certificate, client_cipher, server_cipher, provider,
                                   other_provider):
    # Incorrect cipher is negotiated when both ciphers are PQ_TLS_1_0_2020_12 with
    # openssl 1.0.2, boringssl, and libressl libcryptos
    if all([
        client_cipher == Ciphers.PQ_TLS_1_0_2020_12,
        server_cipher == Ciphers.PQ_TLS_1_0_2020_12,
        any([
            libcrypto in get_flag(S2N_PROVIDER_VERSION)
            for libcrypto in [
                "boringssl",
                "libressl",
                "openssl-1.0.2"
            ]
        ])
    ]):
        pytest.skip()

    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        insecure=True,
        cipher=client_cipher,
        protocol=protocol)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        protocol=protocol,
        cipher=server_cipher,
        cert=certificate.cert,
        key=certificate.key)

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    if pq_enabled():
        expected_result = EXPECTED_RESULTS.get(
            (client_cipher, server_cipher), None)
    else:
        # If PQ is not enabled in s2n, we expect classic handshakes to be negotiated.
        # Leave the expected cipher blank, as there are multiple possibilities - the
        # important thing is that kem and kem_group are NONE.
        expected_result = {"cipher": "", "kem": "NONE", "kem_group": "NONE"}

    # Client and server are both s2n; can make meaningful assertions about negotiation for both
    for results in client.get_results():
        results.assert_success()
        assert_s2n_negotiation_parameters(results, expected_result)

    for results in server.get_results():
        results.assert_success()
        assert_s2n_negotiation_parameters(results, expected_result)


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("cipher", [Ciphers.PQ_TLS_1_0_2020_12], ids=get_parameter_name)
@pytest.mark.parametrize("kem_group", KEM_GROUPS, ids=get_parameter_name)
def test_s2nc_to_oqs_openssl_pq_handshake(managed_process, protocol, cipher, kem_group):
    # If PQ is not enabled in s2n, there is no reason to test against oqs_openssl
    if not pq_enabled():
        return

    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        insecure=True,
        cipher=cipher,
        protocol=protocol)

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        protocol=protocol,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key,
        env_overrides=get_oqs_openssl_override_env_vars(),
        extra_flags=['-groups', kem_group.oqs_name])

    server = managed_process(OpenSSL, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    expected_result = EXPECTED_RESULTS.get((cipher, kem_group), None)

    for results in client.get_results():
        # Client is s2n; can make meaningful assertions about negotiation
        results.assert_success()
        assert_s2n_negotiation_parameters(results, expected_result)

    for results in server.get_results():
        # Server is OQS OpenSSL; just ensure the process exited successfully
        results.assert_success()


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("cipher", [Ciphers.PQ_TLS_1_0_2020_12], ids=get_parameter_name)
@pytest.mark.parametrize("kem_group", KEM_GROUPS, ids=get_parameter_name)
def test_oqs_openssl_to_s2nd_pq_handshake(managed_process, protocol, cipher, kem_group):
    # If PQ is not enabled in s2n, there is no reason to test against oqs_openssl
    if not pq_enabled():
        return

    port = next(available_ports)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        protocol=protocol,
        env_overrides=get_oqs_openssl_override_env_vars(),
        extra_flags=['-groups', kem_group.oqs_name])

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        protocol=protocol,
        cipher=cipher,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key)

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    expected_result = EXPECTED_RESULTS.get((kem_group, cipher), None)

    for results in client.get_results():
        # Client is OQS OpenSSL; just ensure the process exited successfully
        results.assert_success()

    for results in server.get_results():
        # Server is s2n; can make meaningful assertions about negotiation
        results.assert_success()
        assert_s2n_negotiation_parameters(results, expected_result)
