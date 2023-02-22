import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, PROTOCOLS
from common import ProviderOptions, data_bytes, Certificates
from fixtures import managed_process  # lgtm [py/unused-import]
from constants import TEST_OCSP_DIRECTORY
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name
from global_flags import get_flag, S2N_PROVIDER_VERSION


OCSP_CERTS = [Certificates.OCSP, Certificates.OCSP_ECDSA]


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [S2N, OpenSSL, GnuTLS], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N], ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", OCSP_CERTS, ids=get_parameter_name)
def test_s2n_client_ocsp_response(managed_process, cipher, provider, other_provider, curve, protocol, certificate):
    if "boringssl" in get_flag(S2N_PROVIDER_VERSION):
        pytest.skip("s2n-tls client with boringssl does not support ocsp")

    port = next(available_ports)

    random_bytes = data_bytes(128)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        data_to_send=random_bytes,
        enable_client_ocsp=True
    )

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        key=certificate.key,
        cert=certificate.cert,
        ocsp_response={
            "RSA":  TEST_OCSP_DIRECTORY + "ocsp_response.der",
            "EC":   TEST_OCSP_DIRECTORY + "ocsp_ecdsa_response.der"
        }.get(certificate.algorithm),
    )

    kill_marker = None

    if provider == GnuTLS:
        kill_marker = random_bytes

    server = managed_process(
        provider,
        server_options,
        timeout=30,
        kill_marker=kill_marker
    )
    client = managed_process(S2N, client_options, timeout=30)

    for client_results in client.get_results():
        client_results.assert_success()
        assert b"OCSP response received" in client_results.stdout

    for server_results in server.get_results():
        server_results.assert_success()
        # Avoid debugging information that sometimes gets inserted after the first character.
        assert random_bytes[1:] in server_results.stdout or random_bytes[1:] in server_results.stderr


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [GnuTLS, OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("other_provider", [S2N])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", OCSP_CERTS, ids=get_parameter_name)
def test_s2n_server_ocsp_response(managed_process, cipher, provider, other_provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(128)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        data_to_send=random_bytes,
        enable_client_ocsp=True
    )

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        key=certificate.key,
        cert=certificate.cert,
        ocsp_response={
            "RSA":  TEST_OCSP_DIRECTORY + "ocsp_response.der",
            "EC":   TEST_OCSP_DIRECTORY + "ocsp_ecdsa_response.der"
        }.get(certificate.algorithm),
    )

    kill_marker = None
    if provider == GnuTLS:
        # The GnuTLS client hangs for a while after sending. Speed up the tests by killing
        # it immediately after sending the message.
        kill_marker = b"Sent: "

    server = managed_process(S2N, server_options, timeout=2000)
    client = managed_process(provider, client_options,
                             timeout=2000, kill_marker=kill_marker)

    for client_results in client.get_results():
        client_results.assert_success()

        assert any([
            {
                GnuTLS:  b"OCSP Response Information:\n\tResponse Status: Successful",
                OpenSSL: b"OCSP Response Status: successful"
            }.get(provider) in stream for stream in client_results.output_streams()
        ])

    for server_results in server.get_results():
        server_results.assert_success()
        # Avoid debugging information that sometimes gets inserted after the first character.
        assert any(
            [random_bytes[1:] in stream for stream in server_results.output_streams()])
