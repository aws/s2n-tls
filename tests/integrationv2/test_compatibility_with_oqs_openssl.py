import copy
import pytest
import subprocess, os

from common import Certificates, Ciphers, Curves, Protocols, AvailablePorts
from configuration import available_ports, PROVIDERS, PROTOCOLS
from common import Ciphers, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import get_expected_s2n_version
from pip._internal.cli.cmdoptions import cert

oqs_as_server_test_vectors = [
    {"client_ciphers": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "server_ciphers": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE" },
    
]

oqs_as_client_test_vectors = [
    {"client_ciphers": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "server_ciphers": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_cipher": "ECDHE-RSA-AES256-GCM-SHA384", "expected_kem": "NONE" },
]

def get_oqs_openssl_override_env_vars():
    oqs_openssl_install_dir = os.environ["OQS_OPENSSL_1_1_1_INSTALL_DIR"]
    
    override_env_vars = dict()
    override_env_vars["PATH"] = oqs_openssl_install_dir + "/bin"
    override_env_vars["LD_LIBRARY_PATH"] = oqs_openssl_install_dir + "/lib"

    return override_env_vars
    
    

@pytest.mark.parametrize("vector", oqs_as_server_test_vectors)
def test_oqs_openssl_as_server(managed_process, vector):
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
        cipher=vector['client_ciphers'],
        protocol=Protocols.TLS12)

    server_options = ProviderOptions(
        mode = Provider.ServerMode,
        host=host,
        port=port,
        cipher=vector['server_ciphers'],
        protocol=Protocols.TLS12,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key,
        env_overrides=get_oqs_openssl_override_env_vars())

    server = managed_process(OpenSSL, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # OQS OpenSSL is Server, so just check that it had a valid exit code
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(Protocols.TLS12, S2N)

    # Validate S2N Client results were what was expected
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert bytes("KEM: {}".format(vector['expected_kem']).encode('utf-8')) in results.stdout
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout
        
        

@pytest.mark.parametrize("vector", oqs_as_client_test_vectors)
def test_oqs_openssl_as_client(managed_process, vector):
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
        cipher=vector['client_ciphers'],
        protocol=Protocols.TLS12,
        env_overrides=get_oqs_openssl_override_env_vars())

    server_options = ProviderOptions(
        mode = Provider.ServerMode,
        host=host,
        port=port,
        cipher=vector['server_ciphers'],
        protocol=Protocols.TLS12,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key)
    
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(OpenSSL, client_options, timeout=5)

    # OQS OpenSSL is Client, so just check that it had a valid exit code
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    expected_version = get_expected_s2n_version(Protocols.TLS12, S2N)

    # Validate S2N Server results were what was expected
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert bytes("KEM: {}".format(vector['expected_kem']).encode('utf-8')) in results.stdout
        assert bytes("Cipher negotiated: {}".format(vector['expected_cipher']).encode('utf-8')) in results.stdout
        
        
