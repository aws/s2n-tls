# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import copy
import pytest

from configuration import available_ports
from common import Certificates, Ciphers, Curves, Protocols, ProviderOptions, data_bytes
from fixtures import managed_process  # lgtm [py/unused-import]
from providers import Provider, S2N, JavaSSL
from utils import (
    invalid_test_parameters,
    get_parameter_name,
    to_bytes,
)


@pytest.mark.flaky(reruns=5, reruns_delay=2)
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize(
    # TLS 1.3 finally drops support for SSLv2 Client Hellos, and can not be negotiated
    # SSLv2 logic entails different protocol parsing, so make sure we are negotiating
    # the correct protocols.
    "protocol",
    [
        Protocols.TLS12,
        Protocols.TLS11,
        Protocols.TLS10,
    ],
    ids=get_parameter_name,
)
def test_s2n_server_sslv2_client_hello(managed_process, protocol):
    port = next(available_ports)

    # s2nd can receive large amounts of data because all the data is
    # echo'd to stdout unmodified. This lets us compare received to
    # expected easily.
    # We purposefully send a non block aligned number to make sure
    # nothing blocks waiting for more data.
    random_bytes = data_bytes(65519)

    certificate = Certificates.RSA_2048_SHA256

    client_options = ProviderOptions(
        mode=Provider.ServerMode,
        port=port,
        # The cipher must use RSA key exchange. ECDHE is not supported with 
        # SSLv2 formatted client hellos.
        cipher=Ciphers.AES256_SHA256,
        cert=certificate.cert,
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol,
        extra_flags="SSLv2Hello",
    )

    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.data_to_send = None
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.extra_flags = None


    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(JavaSSL, client_options, timeout=5)

    # The client will be one of all supported providers. We
    # just want to make sure there was no exception and that
    # the client exited cleanly.
    for client_results in client.get_results():
        client_results.assert_success()

    # The server is always S2N in this test, so we can examine
    # the stdout reliably.
    for server_results in server.get_results():
        server_results.assert_success()
        assert (
            to_bytes("Actual protocol version: {}".format(protocol))
            in server_results.stdout
        )
        assert random_bytes in server_results.stdout
