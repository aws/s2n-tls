import pytest
import tempfile

from configuration import ALL_TEST_CURVES
from common import ProviderOptions
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N
from utils import invalid_test_parameters, get_parameter_name
from constants import TEST_CERT_DIRECTORY

from test_renegotiate import TEST_PROTOCOLS, S2N_RENEG_OPTION, S2N_RENEG_ACCEPT

APACHE_SERVER_IP = "127.0.0.1"
APACHE_SERVER_PORT = 7777

APACHE_SERVER_CERT = TEST_CERT_DIRECTORY + "apache_server_cert.pem"
APACHE_CLIENT_CERT = TEST_CERT_DIRECTORY + "apache_client_cert.pem"
APACHE_CLIENT_KEY = TEST_CERT_DIRECTORY + "apache_client_key.pem"

CHANGE_CIPHER_SUITE_ENDPOINT = "/change_cipher_suite/"
MUTUAL_AUTH_ENDPOINT = "/mutual_auth/"


def create_get_request(route):
    return f"GET {route} HTTP/1.1\r\nHost: localhost\r\n\r\n"


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("endpoint", [CHANGE_CIPHER_SUITE_ENDPOINT, MUTUAL_AUTH_ENDPOINT])
def test_apache_endpoints_fail_with_no_reneg(managed_process, protocol, endpoint):
    options = ProviderOptions(
        mode=Provider.ClientMode,
        host=APACHE_SERVER_IP,
        port=APACHE_SERVER_PORT,
        curve=ALL_TEST_CURVES[0],
        protocol=protocol,
        trust_store=APACHE_SERVER_CERT,
        cert=APACHE_CLIENT_CERT,
        key=APACHE_CLIENT_KEY,
        use_client_auth=True
    )

    with tempfile.NamedTemporaryFile("w+") as http_request_file:
        http_request_file.write(create_get_request(endpoint))
        http_request_file.flush()
        options.extra_flags = ["--send-file", http_request_file.name]

        s2n_client = managed_process(S2N, options, timeout=20, close_marker="You don't have permission")

        for results in s2n_client.get_results():
            results.assert_success()

            assert b"<title>403 Forbidden</title>" in results.stdout
            assert b"You don't have permission to access this resource." in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
def test_change_cipher_suite_endpoint(managed_process, curve, protocol):
    options = ProviderOptions(
        mode=Provider.ClientMode,
        host=APACHE_SERVER_IP,
        port=APACHE_SERVER_PORT,
        curve=curve,
        protocol=protocol,
        trust_store=APACHE_SERVER_CERT,
    )

    options.extra_flags = [S2N_RENEG_OPTION, S2N_RENEG_ACCEPT]

    with tempfile.NamedTemporaryFile("w+") as http_request_file:
        http_request_file.write(create_get_request(CHANGE_CIPHER_SUITE_ENDPOINT))
        http_request_file.flush()
        options.extra_flags.extend(["--send-file", http_request_file.name])

        s2n_client = managed_process(S2N, options, close_marker="Success.")

        for results in s2n_client.get_results():
            results.assert_success()

            assert b"<title>Change Cipher Suite</title>" in results.stdout
            assert b"Success." in results.stdout


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", TEST_PROTOCOLS, ids=get_parameter_name)
def test_mutual_auth_endpoint(managed_process, curve, protocol):
    options = ProviderOptions(
        mode=Provider.ClientMode,
        host=APACHE_SERVER_IP,
        port=APACHE_SERVER_PORT,
        curve=curve,
        protocol=protocol,
        trust_store=APACHE_SERVER_CERT,
        cert=APACHE_CLIENT_CERT,
        key=APACHE_CLIENT_KEY,
        use_client_auth=True
    )

    options.extra_flags = [S2N_RENEG_OPTION, S2N_RENEG_ACCEPT]

    with tempfile.NamedTemporaryFile("w+") as http_request_file:
        http_request_file.write(create_get_request(MUTUAL_AUTH_ENDPOINT))
        http_request_file.flush()
        options.extra_flags.extend(["--send-file", http_request_file.name])

        s2n_client = managed_process(S2N, options, close_marker="Success.")

        for results in s2n_client.get_results():
            results.assert_success()

            assert b"<title>Mutual Auth</title>" in results.stdout
            assert b"Success." in results.stdout
