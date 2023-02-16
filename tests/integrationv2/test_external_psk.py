import pytest

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, to_bytes
from enum import Enum, auto

# Known value test vectors from https://tools.ietf.org/html/rfc8448#section-4
known_psk_identity = '2c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b00'\
                     '70ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3'\
                     'ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725'\
                     'a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda72'\
                     '1470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfb'\
                     'c388e93343694093934ae4d357'
known_psk_secret = '4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3'

# Arbitrary test vectors
PSK_IDENTITY_LIST = [known_psk_identity, 'psk_identity', 'test_psk_identity']
PSK_SECRET_LIST = [known_psk_secret, 'a6dadae4567876', 'a64dafcd0fc67d2a']
PSK_IDENTITY_NO_MATCH = "PSK_IDENTITY_NO_MATCH"
PSK_SECRET_NO_MATCH = "e9492e1c"
PSK_IDENTITY_NO_MATCH_2 = "PSK_IDENTITY_NO_MATCH_2"
PSK_SECRET_NO_MATCH_2 = "c1e29493fd"

ALL_TEST_CERTS_WITH_EMPTY_CERT = ALL_TEST_CERTS + [None]
PSK_PROVIDERS = [OpenSSL, S2N]


class Outcome(Enum):
    psk_connection = auto()
    full_handshake = auto()
    handshake_failed = auto()


def setup_s2n_psk_params(psk_identity, psk_secret, psk_hash_alg):
    return ['--psk', psk_identity + ',' + psk_secret + ',' + psk_hash_alg]


def setup_openssl_psk_params(psk_identity, psk_secret):
    return ['-psk_identity', psk_identity, '--psk', psk_secret]


def setup_provider_options(mode, port, cipher, curve, certificate, data_to_send, client_psk_params):
    options = ProviderOptions(
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        protocol=Protocols.TLS13,
        data_to_send=data_to_send,
        mode=mode,
        extra_flags=client_psk_params)
    if certificate:
        options.key = certificate.key
        options.cert = certificate.cert
        options.trust_store = certificate.cert
    return options


def get_psk_hash_alg_from_cipher(cipher):
    # S2N supports only SHA256 and SHA384 PSK Hash Algorithms
    if 'SHA256' in cipher.name:
        return 'SHA256'
    elif 'SHA384' in cipher.name:
        return 'SHA384'
    else:
        return None


def skip_invalid_psk_tests(provider, psk_hash_alg):
    # If the PSK hash algorithm is None, it is not supported and we can safely skip the test case.
    if psk_hash_alg is None:
        pytest.skip()

    # In OpenSSL, PSK works only with TLS1.3 ciphersuites based on SHA256 hash algorithm which includes
    # all TLS1.3 ciphersuites supported by S2N except TLS_AES_256_GCM_SHA384.
    if provider == OpenSSL and psk_hash_alg == 'SHA384':
        pytest.skip()


def validate_negotiated_psk_s2n(outcome, psk_identity, results):
    if outcome == Outcome.psk_connection:
        assert to_bytes("Negotiated PSK identity: {}".format(
            psk_identity)) in results.stdout
    elif outcome == Outcome.full_handshake:
        assert to_bytes("Negotiated PSK identity: {}".format(
            psk_identity)) not in results.stdout
    else:
        assert results.exit_code != 0
        assert to_bytes(
            "Failed to negotiate: 'TLS alert received'") in results.stderr


def validate_negotiated_psk_openssl(outcome, results):
    if outcome == Outcome.psk_connection:
        assert to_bytes("extension \"psk\"") in results.stdout
    elif outcome == Outcome.full_handshake:
        assert to_bytes(
            "SSL_connect:SSLv3/TLS read server certificate") in results.stderr
    else:
        assert to_bytes("SSL_accept:error in error") in results.stderr


def test_nothing():
    """
    Sometimes the external psk test parameters in combination with the s2n libcrypto
    results in no test cases existing. In this case, pass a nothing test to avoid
    marking the entire codebuild run as failed.
    """
    assert True


"""
Basic S2N server happy case.

Tests a single psk connection with no fallback option.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", PSK_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("psk_identity", PSK_IDENTITY_LIST, ids=get_parameter_name)
@pytest.mark.parametrize("psk_secret", PSK_SECRET_LIST, ids=get_parameter_name)
def test_s2n_server_psk_connection(managed_process, cipher, curve, protocol, provider, other_provider, psk_identity,
                                   psk_secret):
    port = next(available_ports)
    random_bytes = data_bytes(10)
    psk_hash_alg = get_psk_hash_alg_from_cipher(cipher)
    skip_invalid_psk_tests(provider, psk_hash_alg)

    if provider == S2N:
        client_psk_params = setup_s2n_psk_params(
            psk_identity, psk_secret, psk_hash_alg)
    else:
        client_psk_params = setup_openssl_psk_params(psk_identity, psk_secret)
    client_options = setup_provider_options(
        provider.ClientMode, port, cipher, curve, None, random_bytes, client_psk_params)

    server_psk_params = setup_s2n_psk_params(
        psk_identity, psk_secret, psk_hash_alg)
    server_options = setup_provider_options(
        S2N.ServerMode, port, cipher, curve, None, None, server_psk_params)

    server = managed_process(
        S2N, server_options, timeout=5, close_marker=str(random_bytes))
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()
        if provider == S2N:
            validate_negotiated_psk_s2n(
                Outcome.psk_connection, psk_identity, results)
        else:
            validate_negotiated_psk_openssl(Outcome.psk_connection, results)

    for results in server.get_results():
        results.assert_success()
        validate_negotiated_psk_s2n(
            Outcome.psk_connection, psk_identity, results)
        assert random_bytes in results.stdout


"""
Tests S2N server's behavior with multiple PSKs and no fallback options. 

Note that OpenSSL does not support multiple PSKs. 
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", PSK_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("psk_identity", PSK_IDENTITY_LIST, ids=get_parameter_name)
@pytest.mark.parametrize("psk_secret", PSK_SECRET_LIST, ids=get_parameter_name)
def test_s2n_server_multiple_psks(managed_process, cipher, curve, protocol, provider, other_provider, psk_identity,
                                  psk_secret):
    port = next(available_ports)
    random_bytes = data_bytes(10)
    psk_hash_alg = get_psk_hash_alg_from_cipher(cipher)
    skip_invalid_psk_tests(provider, psk_hash_alg)

    client_psk_params = []
    if provider == OpenSSL:
        """
        OpenSSL Provider does not support multiple PSKs in the same connection, 
        the last psk parameter is the psk parameter used in the connection. 
        """
        client_psk_params.extend(setup_openssl_psk_params(
            PSK_IDENTITY_NO_MATCH, PSK_SECRET_NO_MATCH))
        client_psk_params.extend(
            setup_openssl_psk_params(psk_identity, psk_secret))
    else:
        client_psk_params.extend(setup_s2n_psk_params(
            PSK_IDENTITY_NO_MATCH, PSK_SECRET_NO_MATCH, psk_hash_alg))
        client_psk_params.extend(setup_s2n_psk_params(
            psk_identity, psk_secret, psk_hash_alg))
    client_options = setup_provider_options(
        provider.ClientMode, port, cipher, curve, None, random_bytes, client_psk_params)

    server_psk_params = setup_s2n_psk_params(
        psk_identity, psk_secret, psk_hash_alg)
    server_psk_params.extend(setup_s2n_psk_params(
        PSK_IDENTITY_NO_MATCH_2, PSK_SECRET_NO_MATCH_2, psk_hash_alg))
    server_options = setup_provider_options(
        S2N.ServerMode, port, cipher, curve, None, None, server_psk_params)

    server = managed_process(
        S2N, server_options, timeout=5, close_marker=str(random_bytes))
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()
        if provider == S2N:
            validate_negotiated_psk_s2n(
                Outcome.psk_connection, psk_identity, results)
        else:
            validate_negotiated_psk_openssl(Outcome.psk_connection, results)

    for results in server.get_results():
        results.assert_success()
        validate_negotiated_psk_s2n(
            Outcome.psk_connection, psk_identity, results)
        assert random_bytes in results.stdout


"""
Tests S2N Server's fallback to full handshake.

Verify S2N Server's fallback behavior with an invalid PSK parameter and a valid certificate as the input.

Note that S2N Server succeeds with a full handshake when an invalid PSK parameter and an empty 
certificate is provided as the input, as S2N Server uses a default certificate if a certificate is not provided 
as the input.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", PSK_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("psk_identity", PSK_IDENTITY_LIST, ids=get_parameter_name)
@pytest.mark.parametrize("psk_secret", PSK_SECRET_LIST, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS_WITH_EMPTY_CERT, ids=get_parameter_name)
def test_s2n_server_full_handshake(managed_process, cipher, curve, protocol, provider, other_provider, psk_identity,
                                   psk_secret, certificate):
    port = next(available_ports)
    random_bytes = data_bytes(10)
    psk_hash_alg = get_psk_hash_alg_from_cipher(cipher)
    skip_invalid_psk_tests(provider, psk_hash_alg)

    if provider == S2N:
        client_psk_params = setup_s2n_psk_params(
            psk_identity, psk_secret, psk_hash_alg)
    else:
        client_psk_params = setup_openssl_psk_params(psk_identity, psk_secret)
    client_options = setup_provider_options(
        provider.ClientMode, port, cipher, curve, certificate, random_bytes, client_psk_params)

    server_psk_params = setup_s2n_psk_params(
        PSK_IDENTITY_NO_MATCH, PSK_SECRET_NO_MATCH, psk_hash_alg)
    server_options = setup_provider_options(
        S2N.ServerMode, port, cipher, curve, certificate, None, server_psk_params)

    server = managed_process(
        S2N, server_options, timeout=5, close_marker=str(random_bytes))
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()
        if provider == S2N:
            validate_negotiated_psk_s2n(
                Outcome.full_handshake, psk_identity, results)
        else:
            validate_negotiated_psk_openssl(Outcome.full_handshake, results)

    for results in server.get_results():
        results.assert_success()
        validate_negotiated_psk_s2n(
            Outcome.full_handshake, PSK_IDENTITY_NO_MATCH, results)
        assert random_bytes in results.stdout


"""
Basic S2N client happy case.

Tests a single psk connection with no fallback option.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", PSK_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("psk_identity", PSK_IDENTITY_LIST, ids=get_parameter_name)
@pytest.mark.parametrize("psk_secret", PSK_SECRET_LIST, ids=get_parameter_name)
def test_s2n_client_psk_connection(managed_process, cipher, curve, protocol, provider, other_provider, psk_identity,
                                   psk_secret):
    port = next(available_ports)
    random_bytes = data_bytes(10)
    psk_hash_alg = get_psk_hash_alg_from_cipher(cipher)
    skip_invalid_psk_tests(provider, psk_hash_alg)

    client_psk_params = setup_s2n_psk_params(
        psk_identity, psk_secret, psk_hash_alg)
    client_options = setup_provider_options(
        S2N.ClientMode, port, cipher, curve, None, random_bytes, client_psk_params)

    if provider == S2N:
        server_psk_params = setup_s2n_psk_params(
            psk_identity, psk_secret, psk_hash_alg)
    else:
        server_psk_params = setup_openssl_psk_params(psk_identity, psk_secret)
        server_psk_params += ['-nocert']
    server_options = setup_provider_options(
        provider.ServerMode, port, cipher, curve, None, None, server_psk_params)

    server = managed_process(provider, server_options,
                             timeout=5, close_marker=str(random_bytes))
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()
        validate_negotiated_psk_s2n(
            Outcome.psk_connection, psk_identity, results)

    for results in server.get_results():
        results.assert_success()
        if provider == S2N:
            validate_negotiated_psk_s2n(
                Outcome.psk_connection, psk_identity, results)
        else:
            validate_negotiated_psk_openssl(Outcome.psk_connection, results)
        assert random_bytes in results.stdout


"""
Tests S2N client's behavior with multiple PSKs and no fallback option. 

Note that OpenSSL does not support multiple PSKs. 
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", PSK_PROVIDERS, ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("psk_identity", PSK_IDENTITY_LIST, ids=get_parameter_name)
@pytest.mark.parametrize("psk_secret", PSK_SECRET_LIST, ids=get_parameter_name)
def test_s2n_client_multiple_psks(managed_process, cipher, curve, protocol, provider, other_provider, psk_identity,
                                  psk_secret):
    port = next(available_ports)
    random_bytes = data_bytes(10)
    psk_hash_alg = get_psk_hash_alg_from_cipher(cipher)
    skip_invalid_psk_tests(provider, psk_hash_alg)

    client_psk_params = setup_s2n_psk_params(
        psk_identity, psk_secret, psk_hash_alg)
    client_psk_params.extend(setup_s2n_psk_params(
        PSK_IDENTITY_NO_MATCH, PSK_SECRET_NO_MATCH, psk_hash_alg))
    client_options = setup_provider_options(
        S2N.ClientMode, port, cipher, curve, None, random_bytes, client_psk_params)

    server_psk_params = []
    if provider == OpenSSL:
        """
        OpenSSL Provider does not support multiple PSKs in the same connection, 
        the last psk params is the final psk used in the connection. 
        """
        server_psk_params.extend(setup_openssl_psk_params(
            PSK_IDENTITY_NO_MATCH_2, PSK_SECRET_NO_MATCH_2))
        server_psk_params.extend(
            setup_openssl_psk_params(psk_identity, psk_secret))
        server_psk_params += ['-nocert']
    else:
        server_psk_params.extend(setup_s2n_psk_params(
            PSK_IDENTITY_NO_MATCH_2, PSK_SECRET_NO_MATCH_2, psk_hash_alg))
        server_psk_params.extend(setup_s2n_psk_params(
            psk_identity, psk_secret, psk_hash_alg))
    server_options = setup_provider_options(
        provider.ServerMode, port, cipher, curve, None, None, server_psk_params)

    server = managed_process(provider, server_options,
                             timeout=5, close_marker=str(random_bytes))
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()
        validate_negotiated_psk_s2n(
            Outcome.psk_connection, psk_identity, results)

    for results in server.get_results():
        results.assert_success()
        if provider == S2N:
            validate_negotiated_psk_s2n(
                Outcome.psk_connection, psk_identity, results)
        else:
            validate_negotiated_psk_openssl(Outcome.psk_connection, results)
        assert random_bytes in results.stdout


"""
S2N Client fails to succeed with a handshake when an invalid PSK parameter
and an invalid certificate is provided as the input.

Note that we cannot use S2N Server as a provider input for this test as S2N Server 
uses a default certificate if a certificate is not provided as the input.
"""


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("psk_identity", PSK_IDENTITY_LIST, ids=get_parameter_name)
@pytest.mark.parametrize("psk_secret", PSK_SECRET_LIST, ids=get_parameter_name)
def test_s2n_client_psk_handshake_failure(managed_process, cipher, curve, protocol, provider, psk_identity, psk_secret):
    port = next(available_ports)
    random_bytes = data_bytes(10)
    psk_hash_alg = get_psk_hash_alg_from_cipher(cipher)
    skip_invalid_psk_tests(provider, psk_hash_alg)

    client_psk_params = setup_s2n_psk_params(
        psk_identity, psk_secret, psk_hash_alg)
    client_options = setup_provider_options(
        S2N.ClientMode, port, cipher, curve, None, random_bytes, client_psk_params)

    server_psk_params = setup_openssl_psk_params(
        PSK_IDENTITY_NO_MATCH, PSK_SECRET_NO_MATCH)
    server_psk_params += ['-nocert']
    server_options = setup_provider_options(
        provider.ServerMode, port, cipher, curve, None, None, server_psk_params)

    server = managed_process(provider, server_options,
                             timeout=5, close_marker=str(random_bytes))
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        assert to_bytes(
            "Failed to negotiate: 'TLS alert received'") in results.stderr
        validate_negotiated_psk_s2n(
            Outcome.handshake_failed, psk_identity, results)

    for results in server.get_results():
        assert to_bytes("SSL_accept:error in error") in results.stderr
        validate_negotiated_psk_openssl(Outcome.handshake_failed, results)
        assert random_bytes not in results.stdout
