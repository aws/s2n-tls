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
#include "tests/testlib/s2n_testlib.h"
#include "tls/extensions/s2n_quic_transport_params.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls13.h"

static const uint8_t TEST_DATA[] = "These are transport parameters";

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* Test should_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Safety check */
        EXPECT_FALSE(s2n_quic_transport_parameters_extension.should_send(NULL));

        /* Don't send if quic not enabled (default) */
        EXPECT_FALSE(s2n_quic_transport_parameters_extension.should_send(conn));

        /* Send if quic enabled */
        EXPECT_SUCCESS(s2n_config_enable_quic(config));
        EXPECT_TRUE(s2n_quic_transport_parameters_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test if_missing */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Safety check */
        EXPECT_FAILURE_WITH_ERRNO(s2n_quic_transport_parameters_extension.if_missing(NULL), S2N_ERR_NULL);

        /* Succeeds if quic not enabled (default) */
        EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.if_missing(conn));

        /* Fails if quic enabled
         *
         *= https://tools.ietf.org/rfc/rfc9001.txt#8.2
         *= type=test
         *# Endpoints MUST send the quic_transport_parameters extension; endpoints that receive
         *# ClientHello or EncryptedExtensions messages without the quic_transport_parameters
         *# extension MUST close the connection with an error of type 0x016d (equivalent to a fatal
         *# TLS missing_extension alert
         **/
        EXPECT_SUCCESS(s2n_config_enable_quic(config));
        EXPECT_FAILURE_WITH_ALERT(s2n_quic_transport_parameters_extension.if_missing(conn),
                S2N_ERR_MISSING_EXTENSION, S2N_TLS_ALERT_MISSING_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test send */
    {
        /* Safety checks */
        {
            struct s2n_stuffer out = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_FAILURE_WITH_ERRNO(s2n_quic_transport_parameters_extension.send(NULL, &out), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_quic_transport_parameters_extension.send(conn, NULL), S2N_ERR_NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Writes transport parameters */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_enable_quic(config));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_quic_transport_parameters(conn, TEST_DATA, sizeof(TEST_DATA)));

            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.send(conn, &out));
            EXPECT_BYTEARRAY_EQUAL(out.blob.data, TEST_DATA, sizeof(TEST_DATA));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

        /* Writes empty transport parameters */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_enable_quic(config));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.send(conn, &out));
            EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };
    };

    /* Test recv */
    {
        /* Safety checks */
        {
            struct s2n_stuffer extension = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_FAILURE_WITH_ERRNO(s2n_quic_transport_parameters_extension.recv(NULL, &extension), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_quic_transport_parameters_extension.recv(conn, NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_quic_transport_parameters_extension.recv(conn, &extension),
                    S2N_ERR_UNSUPPORTED_EXTENSION);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Save transport parameters */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_enable_quic(config));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, TEST_DATA, sizeof(TEST_DATA)));

            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.recv(conn, &extension));
            EXPECT_BYTEARRAY_EQUAL(conn->peer_quic_transport_parameters.data, TEST_DATA, sizeof(TEST_DATA));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        };

        /* Save empty transport parameters */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_enable_quic(config));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            struct s2n_stuffer extension = { 0 };

            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.recv(conn, &extension));
            EXPECT_EQUAL(conn->peer_quic_transport_parameters.size, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        };

        /* recv processes the output of send */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_enable_quic(config));

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_quic_transport_parameters(client_conn, TEST_DATA, sizeof(TEST_DATA)));

            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.send(client_conn, &out));
            EXPECT_EQUAL(server_conn->peer_quic_transport_parameters.size, 0);
            EXPECT_SUCCESS(s2n_quic_transport_parameters_extension.recv(server_conn, &out));
            EXPECT_BYTEARRAY_EQUAL(server_conn->peer_quic_transport_parameters.data, TEST_DATA, sizeof(TEST_DATA));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };
    };

    END_TEST();
}
