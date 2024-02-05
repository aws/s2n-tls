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

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_server_signature_algorithms.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test the output of s2n_tls13_cert_req_send() */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_tls13_cert_req_send(server_conn));

        /* verify output */
        uint8_t request_context_length;
        uint16_t extensions_length, extension_size, extension_type;
        EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->handshake.io) > 7);
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&server_conn->handshake.io, &request_context_length));
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server_conn->handshake.io, &extensions_length));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), extensions_length);
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server_conn->handshake.io, &extension_type));
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server_conn->handshake.io, &extension_size));
        EXPECT_EQUAL(request_context_length, 0);
        EXPECT_EQUAL(extension_type, TLS_EXTENSION_SIGNATURE_ALGORITHMS);
        EXPECT_TRUE(extension_size > 0);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test client can receive and parse certificate request */
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        server_conn->actual_protocol_version = S2N_TLS13;
        client_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_tls13_cert_req_send(server_conn));
        EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->handshake.io) > 0);
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, s2n_stuffer_data_available(&server_conn->handshake.io)));
        EXPECT_TRUE(s2n_stuffer_data_available(&client_conn->handshake.io) > 0);
        EXPECT_SUCCESS(s2n_tls13_cert_req_recv(client_conn));

        EXPECT_TRUE(client_conn->handshake_params.server_sig_hash_algs.len > 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test request context length other than 0 fails */
    {
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Request context correct */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 0));
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_MISSING_EXTENSION);

        /* Request context incorrect */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, 2));
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_req_recv(client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    END_TEST();

    return 0;
}
