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

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test s2n_send_empty_cert_chain */
    {
        struct s2n_stuffer out = { 0 };
        /* Magic number 3 is the length of the certificate_length field */
        EXPECT_SUCCESS(s2n_stuffer_alloc(&out, 3));

        EXPECT_SUCCESS(s2n_send_empty_cert_chain(&out));
        EXPECT_EQUAL(s2n_stuffer_data_available(&out), 3);
        uint32_t cert_len;
        EXPECT_SUCCESS(s2n_stuffer_read_uint24(&out, &cert_len));
        EXPECT_EQUAL(cert_len, 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&out));
    };

    /* Client sends the empty cert when no client default chain and key */
    {
        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL));

        /* client send empty cert */
        EXPECT_SUCCESS(s2n_client_cert_send(client_conn));

        /* verify post-conditions */
        EXPECT_TRUE(client_conn->handshake.handshake_type & NO_CLIENT_CERT);
        /* Magic number 3 is the length of the certificate_length field */
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 3);

        uint32_t cert_len;
        EXPECT_SUCCESS(s2n_stuffer_read_uint24(&client_conn->handshake.io, &cert_len));
        EXPECT_EQUAL(cert_len, 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Client fails to send empty cert when S2N_CERT_AUTH_REQUIRED */
    {
        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));

        /* client send empty cert */
        EXPECT_FAILURE(s2n_client_cert_send(client_conn));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Server receives empty cert */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL));

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_OPTIONAL));

        /* client send empty cert */
        EXPECT_SUCCESS(s2n_client_cert_send(client_conn));

        EXPECT_TRUE(client_conn->handshake.handshake_type & NO_CLIENT_CERT);
        /* Magic number 3 is the length of the certificate_length field */
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 3);

        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io, s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), 3);

        /* server receives empty cert */
        EXPECT_SUCCESS(s2n_client_cert_recv(server_conn));
        EXPECT_TRUE(server_conn->handshake.handshake_type & NO_CLIENT_CERT);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    END_TEST();
}
