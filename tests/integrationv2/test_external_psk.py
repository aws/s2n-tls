import copy
import os
import pytest
import time

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes, Curves
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name

CLIENT_PSK_PARAMETERS = [ 
    ['--psk', 'id,secret,S2N_PSK_HMAC_SHA256'],  # No shared PSK 
    ['--psk', 'id1,secret1,S2N_PSK_HMAC_SHA224', # Shared PSK at the wire index 1
     '--psk', 'shared_id,shared_secret,S2N_PSK_HMAC_SHA256'],
    ['--psk', 'id,secret,S2N_PSK_HMAC_SHA224',   # Shared PSK at the wire index 2
     '--psk', 'id1,secret1,S2N_PSK_HMAC_SHA256',
     '--psk', 'shared_id,shared_secret,S2N_PSK_HMAC_SHA256'],
    ['--psk', 'id,secret,S2N_PSK_HMAC_SHA512',   # Invalid psk hmac algorithm obtained 
     '--psk', 'shared_id,shared_secret,S2N_PSK_HMAC_SHA256']
]

SERVER_PSK_PARAMETERS = [
    ['--psk', 'psk_id,psk_secret,S2N_PSK_HMAC_SHA384',
     '--psk', 'shared_id,shared_secret,S2N_PSK_HMAC_SHA256'],
]

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("client_psk_params", CLIENT_PSK_PARAMETERS, ids=get_parameter_name)
@pytest.mark.parametrize("server_psk_params", SERVER_PSK_PARAMETERS, ids=get_parameter_name)
def test_external_psk_s2nc_with_s2nd(managed_process, cipher, protocol, client_psk_params, server_psk_params):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=S2N.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=client_psk_params,
        protocol=protocol)
    
    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.extra_flags = server_psk_params

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    idx = CLIENT_PSK_PARAMETERS.index(client_psk_params)
    
    for results in client.get_results():
        assert results.exception is None
        if idx == 0: 
            assert b"PSK has been chosen with wire index" not in results.stdout
            assert results.exit_code == 0
        elif idx == 1 or idx == 2: 
            assert bytes("PSK has been chosen with wire index: {}".format(idx).encode('utf-8')) in results.stdout
            assert results.exit_code == 0
        elif idx == 3: 
            assert b"Invalid psk hmac algorithm" in results.stderr
            assert results.exit_code != 0
    
    for results in server.get_results():
        assert results.exception is None
        if idx == 0: 
            assert b"PSK has been chosen with wire index" not in results.stdout
        elif idx == 1 or idx == 2:
            assert bytes("PSK has been chosen with wire index: {}".format(idx).encode('utf-8')) in results.stdout
            assert results.exit_code == 0
        elif idx == 3:
            assert results.exit_code != 0
