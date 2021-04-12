import copy
import os
import pytest
import time

from configuration import available_ports
from common import ProviderOptions, Protocols, data_bytes, Ciphers
from fixtures import managed_process
from providers import S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name

shared_psk_identity = '2c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b00'\
                      '70ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3'\
                      'ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725'\
                      'a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda72'\
                      '1470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfb'\
                      'c388e93343694093934ae4d357fad6aacb'

shared_psk_secret = '4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3'

s2n_known_value_psk = '2c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b00'\
                      '70ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3'\
                      'ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725'\
                      'a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda72'\
                      '1470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfb'\
                      'c388e93343694093934ae4d357fad6aacb,'\
                      '4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3,'\
                      'S2N_PSK_HMAC_SHA256'

s2n_client_only_psk = 's2n_client_psk_identity,'\
                      'aea617646faaea6d,'\
                      'S2N_PSK_HMAC_SHA384'\

s2n_server_only_psk = 's2n_server_psk_identity,'\
                      'a6a4dafcd0fc67d2a,'\
                      'S2N_PSK_HMAC_SHA256'\

s2n_invalid_hmac_psk = 'psk_identity,'\
                       'aea617646faaea6d,'\
                       'S2N_PSK_HMAC_SHA512'\

S2N_CLIENT_PSK_PARAMETERS = [ 
    [ '--psk', s2n_client_only_psk ],
    [ '--psk', s2n_known_value_psk ], 
    [ '--psk', s2n_invalid_hmac_psk ],
    [ '--psk', s2n_client_only_psk, '--psk', s2n_known_value_psk ], 
]

S2N_SERVER_PSK_PARAMETERS = [
    [ '--psk', s2n_server_only_psk ],
    [ '--psk', s2n_known_value_psk ],
    [ '--psk', s2n_invalid_hmac_psk ],
    [ '--psk', s2n_server_only_psk, '--psk', s2n_known_value_psk ], 
]

OPENSSL_SERVER_PSK_PARAMETER = [ '-psk_identity', shared_psk_identity, '--psk', shared_psk_secret, '-nocert' ]
OPENSSL_CLIENT_PSK_PARAMETER = [ '-psk_identity', shared_psk_identity, '--psk', shared_psk_secret ]

def s2n_assert_chosen_psk(idx, results):
    if idx == 0:
        assert b"Chosen PSK wire index" not in results.stdout
        assert results.exit_code != 0
    elif idx % 2 == 1:
        assert b"Chosen PSK type: S2N_PSK_TYPE_EXTERNAL" in results.stdout
        assert bytes("Chosen PSK identity: {}".format(shared_psk_identity).encode('utf-8')) in results.stdout
        assert results.exit_code == 0
    elif idx == 2:
        assert b"Invalid psk hmac algorithm" in results.stderr
        assert results.exit_code != 0

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("client_psk_params", S2N_CLIENT_PSK_PARAMETERS, ids=get_parameter_name)
def test_external_psk_s2nc_with_s2nd(managed_process, client_psk_params):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=S2N.ClientMode,
        host="localhost",
        port=port,
        cipher=Ciphers.CHACHA20_POLY1305_SHA256,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=client_psk_params,
        protocol=Protocols.TLS13)
    
    idx = S2N_CLIENT_PSK_PARAMETERS.index(client_psk_params)
    server_psk_params = S2N_SERVER_PSK_PARAMETERS[idx]

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = S2N.ServerMode
    server_options.extra_flags = server_psk_params

    server = managed_process(S2N, server_options, timeout=20)
    client = managed_process(S2N, client_options, timeout=20)

    for results in client.get_results():
        s2n_assert_chosen_psk(idx, results)
        assert results.exception is None

    for results in server.get_results():
        s2n_assert_chosen_psk(idx, results)
        assert results.exception is None

pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("s2n_client_psk_params", S2N_CLIENT_PSK_PARAMETERS, ids=get_parameter_name)
def test_external_psk_s2nc_with_openssl_server(managed_process, s2n_client_psk_params):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=S2N.ClientMode,
        host="localhost",
        port=port,
        cipher=Ciphers.CHACHA20_POLY1305_SHA256,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=s2n_client_psk_params,
        protocol=Protocols.TLS13)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = OpenSSL.ServerMode
    server_options.extra_flags = OPENSSL_SERVER_PSK_PARAMETER
    idx = S2N_CLIENT_PSK_PARAMETERS.index(s2n_client_psk_params)
    server = managed_process(OpenSSL, server_options, timeout=20)
    client = managed_process(S2N, client_options, timeout=20)

    for results in client.get_results():
        s2n_assert_chosen_psk(idx, results)
        assert results.exception is None

    for results in server.get_results():
        if idx == 0:
            assert b"PSK warning: client identity not what we expected" in results.stdout
            assert results.exception is None
            assert results.exit_code == 0
        elif idx % 2 == 1:
            assert b"PSK key given, setting server callback" in results.stdout
            assert results.exception is None
            assert results.exit_code == 0
        else:
            assert results.exit_code != 0

pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("s2n_server_psk_params", S2N_SERVER_PSK_PARAMETERS, ids=get_parameter_name)
def test_external_psk_s2nd_with_openssl_client(managed_process, s2n_server_psk_params):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=OpenSSL.ClientMode,
        host="localhost",
        port=port,
        cipher=Ciphers.CHACHA20_POLY1305_SHA256,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=OPENSSL_CLIENT_PSK_PARAMETER,
        protocol=Protocols.TLS13)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = S2N.ServerMode
    server_options.extra_flags = s2n_server_psk_params
    idx = S2N_SERVER_PSK_PARAMETERS.index(s2n_server_psk_params)
    server = managed_process(S2N, server_options, timeout=20)
    client = managed_process(OpenSSL, client_options, timeout=20)

    for results in server.get_results():
        s2n_assert_chosen_psk(idx, results)
        assert results.exception is None

    for results in client.get_results():
        if idx == 0:
            assert results.exception is None
            assert results.exit_code != 0
        elif idx % 2 == 1:
            assert b"PSK key given, setting client callback" in results.stdout
            assert results.exception is None
            assert results.exit_code == 0
        else:
            assert results.exit_code != 0
