import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, Ciphers, Certificates, Signatures, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


certs = [
    Certificates.RSA_2048_SHA256,
    Certificates.RSA_2048_SHA384,
    Certificates.RSA_PSS_2048_SHA256,
    Certificates.ECDSA_256,
    Certificates.ECDSA_384,
]

all_sigs = [
    Signatures.RSA_SHA1,
    Signatures.RSA_SHA224,
    Signatures.RSA_SHA256,
    Signatures.RSA_SHA384,
    Signatures.RSA_SHA512,
    Signatures.ECDSA_SECP256r1_SHA256,
    Signatures.RSA_PSS_SHA256,
]

# These ciphers don't print out the proper debugging information from s_client,
# so we can't verify the signature algorithm used. When s2n provides the signature
# algorithm to the client, we can enable these.
unsupported_ciphers = [
    Ciphers.AES128_SHA,
    Ciphers.AES256_SHA,
    Ciphers.AES128_SHA256,
    Ciphers.AES256_SHA256,
    Ciphers.AES128_GCM_SHA256,
    Ciphers.AES256_GCM_SHA384,
]


def skip_ciphers(*args, **kwargs):
    cert = kwargs.get('certificate')
    cipher = kwargs.get('cipher')
    protocol = kwargs.get('protocol')
    sigalg = kwargs.get('signature')

    if not cert.compatible_with_cipher(cipher):
        return True

    if not cert.compatible_with_sigalg(sigalg):
        return True

    if protocol is Protocols.TLS13 and sigalg.min_protocol is not Protocols.TLS13:
        return True

    if protocol < sigalg.min_protocol:
        return True

    if cipher in unsupported_ciphers:
        return True

    return invalid_test_parameters(*args, **kwargs)


@pytest.mark.uncollect_if(func=skip_ciphers)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("signature", all_sigs, ids=get_parameter_name)
@pytest.mark.parametrize("client_auth", [True, False], ids=get_parameter_name)
def test_s2n_server_signature_algorithms(managed_process, cipher, provider, protocol, certificate, signature, client_auth):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=False,
        use_client_auth=client_auth,
        client_key_file=certificate.key,
        client_certificate_file=certificate.cert,
        extra_flags=['-sigalgs', signature.name],
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.extra_flags = None
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes('Peer signing digest: {}'.format(signature.sig_digest).encode('utf-8')) in results.stdout
        assert bytes('Peer signature type: {}'.format(signature.sig_type).encode('utf-8')) in results.stdout

    expected_version = get_expected_s2n_version(protocol, provider)

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=skip_ciphers)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("signature", all_sigs, ids=get_parameter_name)
@pytest.mark.parametrize("client_auth", [True, False], ids=get_parameter_name)
def test_s2n_client_signature_algorithms(managed_process, cipher, provider, protocol, certificate, signature, client_auth):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        use_client_auth=client_auth,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags=['-sigalgs', signature.name]

    if client_auth is True:
        client_options.client_trust_store = Certificates.RSA_2048_SHA256_WILDCARD.cert
        server_options.key = Certificates.RSA_2048_SHA256_WILDCARD.key
        server_options.cert = Certificates.RSA_2048_SHA256_WILDCARD.cert

        if signature.sig_type == 'RSA-PSS':
            client_options.client_trust_store = Certificates.RSA_PSS_2048_SHA256.cert
            server_options.key = Certificates.RSA_PSS_2048_SHA256.key
            server_options.cert = Certificates.RSA_PSS_2048_SHA256.cert
        elif signature.sig_type == 'ECDSA':
            client_options.client_trust_store = Certificates.ECDSA_256.cert
            server_options.key = Certificates.ECDSA_256.key
            server_options.cert = Certificates.ECDSA_256.cert

    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes('Shared Signature Algorithms: {}+{}'.format(signature.sig_type, signature.sig_digest).encode('utf-8')) in results.stdout
        assert random_bytes in results.stdout

    expected_version = get_expected_s2n_version(protocol, provider)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in results.stdout
