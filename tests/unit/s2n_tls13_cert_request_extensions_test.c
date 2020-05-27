/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"

#include <string.h>
#include <stdio.h>
#include <s2n.h>

#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/extensions/s2n_server_signature_algorithms.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test client fails to parse certificate request with no extensions */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Write 0 length request context https://tools.ietf.org/html/rfc8446#section-4.3.2 */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        /* write total extension length */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_MISSING_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test client fails to parse certificate request with wrong extension type */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Write supported versions extension instead */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, s2n_extensions_server_supported_versions_size(client_conn)));
        EXPECT_SUCCESS(s2n_extensions_server_supported_versions_send(client_conn, &client_conn->handshake.io));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test extension size greater than actual fails */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, s2n_extensions_server_signature_algorithms_size(client_conn) + 3));
        EXPECT_SUCCESS(s2n_extensions_server_signature_algorithms_send(client_conn, &client_conn->handshake.io));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test extension size smaller than actual fails */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Extension size read inside of parsing the extension will be greater than data available 
         * as overall extension size written here is smaller than was actually written */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, s2n_extensions_server_signature_algorithms_size(client_conn) - 4));
        EXPECT_SUCCESS(s2n_extensions_server_signature_algorithms_send(client_conn, &client_conn->handshake.io));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test correct extension (sig_alg) */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        conn->actual_protocol_version = S2N_TLS13;

        EXPECT_EQUAL(conn->handshake_params.server_sig_hash_algs.len, 0);
        EXPECT_SUCCESS(s2n_tls13_cert_req_send(conn));
        EXPECT_SUCCESS(s2n_tls13_cert_req_recv(conn));
        EXPECT_NOT_EQUAL(conn->handshake_params.server_sig_hash_algs.len, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test correct extension (sig alg) with wrong length */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, s2n_extensions_server_signature_algorithms_size(client_conn)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
        /* From s2n_extensions_server_signature_algorithms_send() */
        uint16_t total_size = s2n_extensions_server_signature_algorithms_size(client_conn);
        uint16_t extension_size = total_size - 4;
        /* Subtract further to make the extension_size smaller than it actually is */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, extension_size - 4));
        EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(client_conn, &client_conn->handshake.io));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_BAD_MESSAGE);

        /* Test again with extension size larger than it actually is */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_TRUE(s2n_stuffer_data_available(&client_conn->handshake.io) == 0);

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, s2n_extensions_server_signature_algorithms_size(client_conn)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, TLS_EXTENSION_SIGNATURE_ALGORITHMS));
        total_size = s2n_extensions_server_signature_algorithms_size(client_conn);
        extension_size = total_size - 4;
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, extension_size + 4));
        EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(client_conn, &client_conn->handshake.io));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Test two of the same extension */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&client_conn->handshake.io, 2 * s2n_extensions_server_signature_algorithms_size(client_conn)));
        EXPECT_SUCCESS(s2n_extensions_server_signature_algorithms_send(client_conn, &client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_extensions_server_signature_algorithms_send(client_conn, &client_conn->handshake.io));

        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_DUPLICATE_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    EXPECT_SUCCESS(s2n_disable_tls13());
    END_TEST();

    return 0;
}
