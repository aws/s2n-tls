import copy
import pytest

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, Certificates, Signatures, data_bytes, Ciphers
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, OpenSSL, GnuTLS
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, to_bytes

all_sigs = [
    Signatures.RSA_SHA1,
    Signatures.RSA_SHA224,
    Signatures.RSA_SHA256,
    Signatures.RSA_SHA384,
    Signatures.RSA_SHA512,
    Signatures.ECDSA_SECP256r1_SHA256,
    Signatures.ECDSA_SECP384r1_SHA384,
    Signatures.ECDSA_SECP521r1_SHA512,
    Signatures.RSA_PSS_RSAE_SHA256,
    Signatures.RSA_PSS_PSS_SHA256,
    Signatures.ECDSA_SHA1,
    Signatures.ECDSA_SHA224,
    Signatures.ECDSA_SHA256,
    Signatures.ECDSA_SHA384,
    Signatures.ECDSA_SHA512,
]


def expected_signature(protocol, signature):
    if protocol < Protocols.TLS12:
        # ECDSA by default hashes with SHA-1.
        #
        # This is inferred from extended version of TLS1.1 rfc- https://www.rfc-editor.org/rfc/rfc4492#section-5.10
        if signature.sig_type == 'ECDSA':
            signature = Signatures.ECDSA_SHA1
        else:
            signature = Signatures.RSA_MD5_SHA1
    return signature


def signature_marker(mode, signature):
    return to_bytes("{mode} signature negotiated: {type}+{digest}"
                    .format(mode=mode.title(), type=signature.sig_type, digest=signature.sig_digest))


def skip_ciphers(*args, **kwargs):
    provider = kwargs.get('provider')
    cert = kwargs.get('certificate')
    cipher = kwargs.get('cipher')
    protocol = kwargs.get('protocol')
    sigalg = kwargs.get('signature')

    if not provider.supports_signature(sigalg):
        return True

    if not cert.compatible_with_cipher(cipher):
        return True

    if not cert.compatible_with_sigalg(sigalg):
        return True

    if protocol > sigalg.max_protocol:
        return True

    if protocol < sigalg.min_protocol:
        return True

    return invalid_test_parameters(*args, **kwargs)


@pytest.mark.uncollect_if(func=skip_ciphers)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL, GnuTLS])
@pytest.mark.parametrize("other_provider", [S2N])
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12, Protocols.TLS11], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("signature", all_sigs, ids=get_parameter_name)
@pytest.mark.parametrize("client_auth", [True, False], ids=lambda val: "client-auth" if val else "no-client-auth")
def test_s2n_server_signature_algorithms(managed_process, cipher, provider, other_provider, protocol, certificate,
                                         signature, client_auth):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=False,
        use_client_auth=client_auth,
        key=certificate.key,
        cert=certificate.cert,
        signature_algorithm=signature,
        protocol=protocol
    )

    if provider == GnuTLS:
        # GnuTLS fails the CA verification. It must be run with this check disabled.
        client_options.extra_flags = ["--no-ca-verification"]

    server_options = copy.copy(client_options)
    server_options.extra_flags = None
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    for results in client.get_results():
        results.assert_success()

    expected_version = get_expected_s2n_version(protocol, provider)

    for results in server.get_results():
        results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in results.stdout
        assert signature_marker(Provider.ServerMode,
                                expected_signature(protocol, signature)) in results.stdout
        assert (signature_marker(Provider.ClientMode,
                                 expected_signature(protocol, signature)) in results.stdout) == client_auth
        assert random_bytes in results.stdout


@pytest.mark.uncollect_if(func=skip_ciphers)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL, GnuTLS])
@pytest.mark.parametrize("other_provider", [S2N])
@pytest.mark.parametrize("protocol", [Protocols.TLS13, Protocols.TLS12, Protocols.TLS11], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("signature", all_sigs, ids=get_parameter_name)
@pytest.mark.parametrize("client_auth", [True, False], ids=lambda val: "client-auth" if val else "no-client-auth")
def test_s2n_client_signature_algorithms(managed_process, cipher, provider, other_provider, protocol, certificate,
                                         signature, client_auth):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        use_client_auth=client_auth,
        key=certificate.key,
        cert=certificate.cert,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.trust_store = certificate.cert
    server_options.signature_algorithm = signature

    kill_marker = None
    if provider == GnuTLS:
        kill_marker = random_bytes

    server = managed_process(provider, server_options,
                             timeout=5, kill_marker=kill_marker)
    client = managed_process(S2N, client_options, timeout=5)

    for results in server.get_results():
        results.assert_success()
        assert any(
            [random_bytes in stream for stream in results.output_streams()])

    expected_version = get_expected_s2n_version(protocol, provider)

    # In versions before TLS1.3, the server uses the negotiated signature scheme for the
    # ServerKeyExchange message. The server only sends the ServerKeyExchange message when using
    # a key exchange method that provides forward secrecy, ie, NOT static RSA.
    # So if using RSA key exchange, there is no actual "negotiated" signature scheme, because
    # the server never sends the client a signature scheme.
    #
    # This mostly has to be inferred from the RFCs, but this blog post is a pretty good summary
    # of the situation: https://timtaubert.de/blog/2016/07/the-evolution-of-signatures-in-tls/
    server_sigalg_used = not cipher.iana_standard_name.startswith(
        "TLS_RSA_WITH_")

    for results in client.get_results():
        results.assert_success()
        assert to_bytes("Actual protocol version: {}".format(
            expected_version)) in results.stdout
        assert signature_marker(
            Provider.ServerMode, expected_signature(protocol, signature)) in results.stdout or not server_sigalg_used
        assert (signature_marker(Provider.ClientMode, expected_signature(protocol, signature))
                in results.stdout) == client_auth
