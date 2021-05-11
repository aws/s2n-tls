import copy
import os
import pytest
import time
import enum

from configuration import available_ports
from common import ProviderOptions, Protocols, data_bytes, Ciphers, Certificates
from fixtures import managed_process
from providers import S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name
from collections import namedtuple
from enum import Enum, auto

# Test Vectors from https://tools.ietf.org/html/rfc8448#section-4
shared_psk_identity = '2c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b00'\
                      '70ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3'\
                      'ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725'\
                      'a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda72'\
                      '1470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfb'\
                      'c388e93343694093934ae4d357'

shared_psk_secret = '4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3'

s2n_known_value_psk_sha256 = shared_psk_identity + ','\
                             + shared_psk_secret + ','\
                             'SHA256'

s2n_known_value_psk_sha384 = shared_psk_identity + ','\
                             + shared_psk_secret + ','\
                             'SHA384'

# Arbitrary Test vectors
s2n_psk_parameters_sha384 = 'psk_identity_sha384,'\
                            'a6dadae4567876,'\
                            'SHA384'\

s2n_psk_parameters_sha256 = 'psk_identity_sha256,'\
                            'a64dafcd0fc67d2a,'\
                            'SHA256'\

openssl_psk_parameters = ['-psk_identity',
                          shared_psk_identity, '--psk', shared_psk_secret]

# PSK Identity marker to assert with openssl logs
psk_identity_marker = [b"2c0",
                       b"35d829359ee5ff7a", b"f4ec900000000262", b"a6494dc486d2c8a3", b"4cb33fa90bf1b007", b"0ad3c498883c9367",
                       b"c09a2be785abc55c", b"d226097a3a982117", b"283f82a03a143efd", b"3ff5dd36d64e861b", b"e7fd61d2827db279",
                       b"cce145077d454a36", b"64d4e6da4d29ee03", b"725a6a4dafcd0fc6", b"7d2aea70529513e3", b"da2677fa5906c5b3",
                       b"f7d8f92f228bda40", b"7b5aea617646fac5", b"c03272e970727c62", b"1a79141ef5f7de65", b"05e5bfbc388e9334",
                       b"3694093934ae4d35"]


class Outcome(enum.Enum):
    psk_connection = auto()
    full_handshake = auto()
    connection_failed = auto()


S2N_TEST_CASE = namedtuple(
    'S2N_TEST_CASE', 'cipher certificate s2nc_params s2nd_params outcome')

S2N_TEST_SUITE = [
    S2N_TEST_CASE(cipher=Ciphers.CHACHA20_POLY1305_SHA256, certificate=None, s2nd_params=[
                  '--psk', s2n_psk_parameters_sha384], s2nc_params=['--psk', s2n_psk_parameters_sha256], outcome=Outcome.connection_failed),
    S2N_TEST_CASE(cipher=Ciphers.AES128_GCM_SHA256, certificate=Certificates.ECDSA_256, s2nd_params=[
                  '--psk', s2n_psk_parameters_sha384], s2nc_params=['--psk', s2n_psk_parameters_sha256], outcome=Outcome.full_handshake),
    S2N_TEST_CASE(cipher=Ciphers.CHACHA20_POLY1305_SHA256, certificate=None, s2nd_params=[
                  '--psk', s2n_known_value_psk_sha256], s2nc_params=['--psk', s2n_known_value_psk_sha256], outcome=Outcome.psk_connection),
    S2N_TEST_CASE(cipher=Ciphers.AES256_GCM_SHA384, certificate=None,  s2nd_params=[
                  '--psk', s2n_known_value_psk_sha384], s2nc_params=['--psk', s2n_known_value_psk_sha384], outcome=Outcome.psk_connection),
    S2N_TEST_CASE(cipher=Ciphers.AES128_GCM_SHA256, certificate=None, s2nd_params=[
                  '--psk', s2n_psk_parameters_sha384, '--psk', s2n_known_value_psk_sha256], s2nc_params=['--psk', s2n_psk_parameters_sha256,
                  '--psk', s2n_known_value_psk_sha256], outcome=Outcome.psk_connection)
]

OPENSSL_TEST_CASE = namedtuple(
    'OPENSSL_TEST_CASE', 'cipher certificate s2n_params openssl_params outcome')

OPENSSL_SERVER_S2NC_TEST_SUITE = [
    # The following test is flaky and is temporarily disabled. See issue: https://github.com/aws/s2n-tls/issues/2818
    # OPENSSL_TEST_CASE(cipher=Ciphers.AES128_GCM_SHA256, certificate=None, s2n_params=[
    #                  '--psk', s2n_known_value_psk_sha256], openssl_params=openssl_psk_parameters, outcome=Outcome.psk_connection),
    OPENSSL_TEST_CASE(cipher=Ciphers.CHACHA20_POLY1305_SHA256, certificate=Certificates.ECDSA_256, s2n_params=[
                      '--psk', s2n_psk_parameters_sha384, '--psk', s2n_psk_parameters_sha256], openssl_params=openssl_psk_parameters, outcome=Outcome.connection_failed),
    OPENSSL_TEST_CASE(cipher=Ciphers.AES256_GCM_SHA384, certificate=None, s2n_params=[
                      '--psk', s2n_psk_parameters_sha384, '--psk', s2n_psk_parameters_sha256], openssl_params=openssl_psk_parameters, outcome=Outcome.connection_failed)
]

OPENSSL_CLIENT_S2ND_TEST_SUITE = [
    OPENSSL_TEST_CASE(cipher=Ciphers.AES128_GCM_SHA256, certificate=None, s2n_params=[
        '--psk', s2n_known_value_psk_sha256], openssl_params=openssl_psk_parameters, outcome=Outcome.psk_connection),
    OPENSSL_TEST_CASE(cipher=Ciphers.CHACHA20_POLY1305_SHA256, certificate=Certificates.ECDSA_256, s2n_params=[
                      '--psk', s2n_psk_parameters_sha384, '--psk', s2n_psk_parameters_sha256], openssl_params=openssl_psk_parameters, outcome=Outcome.full_handshake),
    OPENSSL_TEST_CASE(cipher=Ciphers.AES256_GCM_SHA384, certificate=None, s2n_params=[
                      '--psk', s2n_psk_parameters_sha384, '--psk', s2n_psk_parameters_sha256], openssl_params=openssl_psk_parameters, outcome=Outcome.full_handshake),
    # Note that the following test case's outcome is `full_handshake` instead of `connection_failed` because s2nd uses a default certificate if a certificate is not provided. 
    OPENSSL_TEST_CASE(cipher=Ciphers.AES256_GCM_SHA384, certificate=None, s2n_params=[
                      '--psk', s2n_psk_parameters_sha384, '--psk', s2n_psk_parameters_sha256], openssl_params=openssl_psk_parameters, outcome=Outcome.full_handshake)
]


def validate_negotiated_psk_s2n(outcome, certificate, results):
    if outcome == Outcome.psk_connection:
        assert results.exception is None
        assert results.exit_code == 0
        assert not results.stderr
        assert bytes("Negotiated PSK identity: {}".format(
            shared_psk_identity).encode('utf-8')) in results.stdout
    elif outcome == Outcome.full_handshake:
        assert results.exception is None
        assert results.exit_code == 0
        assert not results.stderr
        assert bytes("Negotiated PSK identity: {}".format(
            shared_psk_identity).encode('utf-8')) not in results.stdout
    else:
        assert results.exit_code != 0


def validate_openssl(outcome, results):
    if outcome == Outcome.psk_connection:
        assert results.exception is None
        assert results.exit_code == 0
        for psk_marker in psk_identity_marker:
            assert psk_marker in results.stdout
    elif outcome == Outcome.full_handshake:
        assert results.exception is None
        assert results.exit_code == 0
    else:
        assert results.exit_code != 0


def validate_random_bytes(outcome, random_bytes, results):
    if outcome == Outcome.psk_connection or outcome == Outcome.full_handshake:
        assert random_bytes in results.stdout
    else:
        assert random_bytes not in results.stdout


@pytest.mark.parametrize("cipher,certificate,s2nc_params,s2nd_params,outcome", S2N_TEST_SUITE)
def test_external_psk_s2nc_with_s2nd(managed_process, cipher, certificate, s2nc_params, s2nd_params, outcome):
    port = next(available_ports)
    random_bytes = data_bytes(64)

    client_options = ProviderOptions(
        mode=S2N.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=False,
        extra_flags=s2nc_params,
        protocol=Protocols.TLS13)

    if certificate:
        client_options.key = certificate.key
        client_options.cert = certificate.cert
        client_options.trust_store = certificate.cert

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = S2N.ServerMode
    server_options.extra_flags = s2nd_params

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    for results in client.get_results():
        validate_negotiated_psk_s2n(outcome, certificate, results)

    for results in server.get_results():
        validate_negotiated_psk_s2n(outcome, certificate, results)
        validate_random_bytes(outcome, random_bytes, results)


@pytest.mark.parametrize("cipher,certificate,s2nd_params,openssl_params,outcome", OPENSSL_CLIENT_S2ND_TEST_SUITE)
def test_external_psk_s2nd_with_openssl_client(managed_process, certificate, cipher, s2nd_params, openssl_params, outcome):
    port = next(available_ports)
    random_bytes = data_bytes(64)

    client_options = ProviderOptions(
        mode=OpenSSL.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=False,
        extra_flags=openssl_params,
        protocol=Protocols.TLS13)

    if certificate:
        client_options.key = certificate.key
        client_options.cert = certificate.cert
        client_options.trust_store = certificate.cert

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = S2N.ServerMode
    server_options.extra_flags = s2nd_params
    client = managed_process(OpenSSL, client_options, timeout=5)
    server = managed_process(S2N, server_options, timeout=5)

    for results in client.get_results():
        validate_openssl(outcome, results)

    for results in server.get_results():
        validate_negotiated_psk_s2n(outcome, certificate, results)
        validate_random_bytes(outcome, random_bytes, results)


@pytest.mark.parametrize("cipher,certificate,s2nc_params,openssl_params,outcome", OPENSSL_SERVER_S2NC_TEST_SUITE)
def test_external_psk_s2nc_with_openssl_server(managed_process, cipher, certificate, s2nc_params, openssl_params, outcome):
    port = next(available_ports)
    random_bytes = data_bytes(64)

    client_options = ProviderOptions(
        mode=S2N.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=False,
        extra_flags=s2nc_params,
        protocol=Protocols.TLS13)

    if certificate:
        client_options.key = certificate.key
        client_options.cert = certificate.cert
        client_options.trust_store = certificate.cert

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = OpenSSL.ServerMode

    if certificate:
        server_options.extra_flags = openssl_params
    else:
        server_options.extra_flags = openssl_params + ['-nocert']

    client = managed_process(S2N, client_options, timeout=5)
    server = managed_process(OpenSSL, server_options, timeout=5)

    for results in client.get_results():
        validate_negotiated_psk_s2n(outcome, certificate, results)

    for results in server.get_results():
        validate_openssl(outcome, results)
