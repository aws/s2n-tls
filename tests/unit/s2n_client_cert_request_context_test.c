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
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    uint8_t empty_cert_len = 3;
    uint8_t certificate_context_len = 1;

    /* Test certificate_request_context sent/recv only when TLS 1.3 enabled */
    {
        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL));

        /* Without TLS 1.3 enabled, there is no context length */
        EXPECT_SUCCESS(s2n_client_cert_send(client_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), empty_cert_len);
        EXPECT_SUCCESS(s2n_client_cert_recv(client_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 0);

        /* With TLS 1.3 enabled, there is a context length */
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        client_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_client_cert_send(client_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), empty_cert_len + certificate_context_len);
        EXPECT_SUCCESS(s2n_client_cert_recv(client_conn));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test certificate_request_context is zero-length as currently
     * only used for handshake authentication */
    {
        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_OPTIONAL));
        client_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_client_cert_send(client_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), empty_cert_len + certificate_context_len);

        uint8_t expected_certificate_request_context_len = 0;
        uint8_t actual_certificate_request_context_len;

        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&client_conn->handshake.io, &actual_certificate_request_context_len));
        EXPECT_EQUAL(expected_certificate_request_context_len, actual_certificate_request_context_len);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* Test failure case of non-zero certificate_request_context */
    {
        struct s2n_config *server_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_OPTIONAL));
        server_conn->actual_protocol_version = S2N_TLS13;

        /* write non-zero certificate_request_context + empty cert */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&server_conn->handshake.io, 2));
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&server_conn->handshake.io, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_cert_recv(server_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_config_free(server_config));
    };

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    END_TEST();
}
