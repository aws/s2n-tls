import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, get_expected_openssl_version, \
    to_bytes, get_expected_gnutls_version


def test_nothing():
    """
    Sometimes the version negotiation test parameters in combination with the s2n
    libcrypto results in no test cases existing. In this case, pass a nothing test to
    avoid marking the entire codebuild run as failed.
    """
    assert True


def invalid_version_negotiation_test_parameters(*args, **kwargs):
    # Since s2nd/s2nc will always be using TLS 1.3, make sure the libcrypto is compatible
    if invalid_test_parameters(**{
        "provider": S2N,
        "protocol": Protocols.TLS13
    }):
        return True

    return invalid_test_parameters(*args, **kwargs)


@pytest.mark.uncollect_if(func=invalid_version_negotiation_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS12, Protocols.TLS11, Protocols.TLS10], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2nc_tls13_negotiates_tls12(managed_process, cipher, curve, certificate, protocol, provider, other_provider):
    port = next(available_ports)

    random_bytes = data_bytes(24)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=Protocols.TLS13
    )

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.protocol = protocol

    kill_marker = None
    if provider == GnuTLS:
        kill_marker = random_bytes

    server = managed_process(provider, server_options,
                             timeout=5, kill_marker=kill_marker)
    client = managed_process(S2N, client_options, timeout=5)

    client_version = get_expected_s2n_version(Protocols.TLS13, provider)
    actual_version = get_expected_s2n_version(protocol, provider)

    for results in client.get_results():
        results.assert_success()
        assert to_bytes("Client protocol version: {}".format(
            client_version)) in results.stdout
        assert to_bytes("Actual protocol version: {}".format(
            actual_version)) in results.stdout

    for results in server.get_results():
        results.assert_success()
        # This check only cares about S2N. Trying to maintain expected output of other providers doesn't add benefit to
        # whether the S2N client was able to negotiate a lower TLS version.
        if provider is S2N:
            # The client sends a TLS 1.3 client hello so a client protocol version of TLS 1.3 should always be expected.
            assert to_bytes("Client protocol version: {}".format(
                Protocols.TLS13.value)) in results.stdout
            assert to_bytes("Actual protocol version: {}".format(
                actual_version)) in results.stdout

        assert any([
            random_bytes[1:] in stream
            for stream in results.output_streams()
        ])


@pytest.mark.uncollect_if(func=invalid_version_negotiation_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS12, Protocols.TLS11, Protocols.TLS10], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
def test_s2nd_tls13_negotiates_tls12(managed_process, cipher, curve, certificate, protocol, provider, other_provider):
    port = next(available_ports)

    random_bytes = data_bytes(24)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol
    )

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    # When the protocol is set to TLS13, the s2n server provider will default to using
    # all ciphers, not just the TLS13 ciphers. This is the desired behavior for this test.
    server_options.protocol = Protocols.TLS13

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    server_version = get_expected_s2n_version(Protocols.TLS13, provider)
    actual_version = get_expected_s2n_version(protocol, provider)

    for results in client.get_results():
        results.assert_success()
        if provider is S2N:
            # The client will get the server version from the SERVER HELLO, which will be the negotiated version
            assert to_bytes("Server protocol version: {}".format(
                actual_version)) in results.stdout
            assert to_bytes("Actual protocol version: {}".format(
                actual_version)) in results.stdout
        elif provider is OpenSSL:
            # This check cares about other providers because we want to know that they did negotiate the version
            # that our S2N server intended to negotiate.
            openssl_version = get_expected_openssl_version(protocol)
            assert to_bytes("Protocol  : {}".format(
                openssl_version)) in results.stdout
        elif provider is GnuTLS:
            gnutls_version = get_expected_gnutls_version(protocol)
            assert to_bytes(f"Version: {gnutls_version}") in results.stdout

    for results in server.get_results():
        results.assert_success()
        assert (
            to_bytes("Server protocol version: {}".format(server_version))
            in results.stdout
        )
        assert (
            to_bytes("Actual protocol version: {}".format(actual_version))
            in results.stdout
        )
        assert random_bytes[1:] in results.stdout
