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

#include "tls/s2n_quic_support.h"

#include "s2n_test.h"
#include "tls/s2n_connection.h"

static const uint8_t TEST_DATA[] = "test";

static int s2n_test_noop_secret_handler(void *context, struct s2n_connection *conn,
        s2n_secret_type_t secret_type, uint8_t *secret, uint8_t secret_size)
{
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test QUIC is not allowed if TLS1.3 not fully supported. */
    if (!s2n_is_tls13_fully_supported()) {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_enable_quic(config));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_enable_quic(conn), S2N_ERR_RSA_PSS_NOT_SUPPORTED);
        EXPECT_FALSE(conn->quic_enabled);

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_config(conn, config), S2N_ERR_RSA_PSS_NOT_SUPPORTED);
        EXPECT_NOT_EQUAL(config, conn->config);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
        END_TEST();
    }

    /* Test s2n_config_enable_quic */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_FALSE(config->quic_enabled);

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_FALSE(s2n_connection_is_quic_enabled(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_FALSE(s2n_connection_is_quic_enabled(conn));

        /* Check error handling */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_enable_quic(NULL), S2N_ERR_NULL);
            EXPECT_FALSE(config->quic_enabled);
            EXPECT_FALSE(s2n_connection_is_quic_enabled(conn));
        };

        /* Check success */
        {
            EXPECT_SUCCESS(s2n_config_enable_quic(config));
            EXPECT_TRUE(config->quic_enabled);
            EXPECT_TRUE(s2n_connection_is_quic_enabled(conn));

            /* Enabling QUIC again still succeeds */
            EXPECT_SUCCESS(s2n_config_enable_quic(config));
            EXPECT_TRUE(config->quic_enabled);
            EXPECT_TRUE(s2n_connection_is_quic_enabled(conn));
        };

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test s2n_connection_enable_quic */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_FALSE(s2n_connection_is_quic_enabled(conn));

        /* Check error handling */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_enable_quic(NULL), S2N_ERR_NULL);
            EXPECT_FALSE(s2n_connection_is_quic_enabled(conn));
        };

        /* Check success */
        {
            EXPECT_SUCCESS(s2n_connection_enable_quic(conn));
            EXPECT_TRUE(s2n_connection_is_quic_enabled(conn));

            /* Enabling QUIC again still succeeds */
            EXPECT_SUCCESS(s2n_connection_enable_quic(conn));
            EXPECT_TRUE(s2n_connection_is_quic_enabled(conn));
        };

        /* Check with config enabled too */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_FALSE(config->quic_enabled);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_config_enable_quic(config));
            EXPECT_TRUE(s2n_connection_is_quic_enabled(conn));

            EXPECT_SUCCESS(s2n_config_free(config));
        };

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test that if a connection enables quic via the config,
     * quic stays enabled for the connection even if the config changes.
     */
    {
        struct s2n_config *non_quic_config = s2n_config_new();
        EXPECT_NOT_NULL(non_quic_config);

        struct s2n_config *quic_config = s2n_config_new();
        EXPECT_NOT_NULL(quic_config);
        EXPECT_SUCCESS(s2n_config_enable_quic(quic_config));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        EXPECT_FALSE(s2n_connection_is_quic_enabled(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, non_quic_config));
        EXPECT_FALSE(s2n_connection_is_quic_enabled(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, quic_config));
        EXPECT_TRUE(s2n_connection_is_quic_enabled(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, non_quic_config));
        EXPECT_TRUE(s2n_connection_is_quic_enabled(conn));

        EXPECT_SUCCESS(s2n_config_free(non_quic_config));
        EXPECT_SUCCESS(s2n_config_free(quic_config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_connection_set_quic_transport_parameters */
    {
        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_quic_transport_parameters(NULL, TEST_DATA, sizeof(TEST_DATA)),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_quic_transport_parameters(&conn, NULL, sizeof(TEST_DATA)),
                    S2N_ERR_NULL);
            EXPECT_SUCCESS(s2n_connection_set_quic_transport_parameters(&conn, TEST_DATA, 0));
            EXPECT_EQUAL(conn.our_quic_transport_parameters.size, 0);
        };

        /* Set transport data */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            s2n_connection_set_quic_transport_parameters(conn, TEST_DATA, sizeof(TEST_DATA));
            EXPECT_BYTEARRAY_EQUAL(conn->our_quic_transport_parameters.data, TEST_DATA, sizeof(TEST_DATA));

            /* Set again */
            const uint8_t other_data[] = "other parameters";
            s2n_connection_set_quic_transport_parameters(conn, other_data, sizeof(other_data));
            EXPECT_BYTEARRAY_EQUAL(conn->our_quic_transport_parameters.data, other_data, sizeof(other_data));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_connection_get_quic_transport_parameters */
    {
        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            const uint8_t *data_buffer = NULL;
            uint16_t data_buffer_len = 0;

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_quic_transport_parameters(NULL, &data_buffer, &data_buffer_len),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_quic_transport_parameters(&conn, NULL, &data_buffer_len),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_quic_transport_parameters(&conn, &data_buffer, NULL),
                    S2N_ERR_NULL);
        };

        /* Get empty transport parameters */
        {
            const uint8_t *data_buffer = TEST_DATA;
            uint16_t data_buffer_len = sizeof(TEST_DATA);

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_connection_get_quic_transport_parameters(conn, &data_buffer, &data_buffer_len));
            EXPECT_EQUAL(data_buffer, NULL);
            EXPECT_EQUAL(data_buffer_len, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Get transport parameters */
        {
            const uint8_t *data_buffer = NULL;
            uint16_t data_buffer_len = 0;

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_alloc(&conn->peer_quic_transport_parameters, sizeof(TEST_DATA)));
            EXPECT_MEMCPY_SUCCESS(conn->peer_quic_transport_parameters.data, TEST_DATA, sizeof(TEST_DATA));

            EXPECT_SUCCESS(s2n_connection_get_quic_transport_parameters(conn, &data_buffer, &data_buffer_len));
            EXPECT_EQUAL(data_buffer, conn->peer_quic_transport_parameters.data);
            EXPECT_EQUAL(data_buffer_len, conn->peer_quic_transport_parameters.size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_connection_set_secret_callback */
    {
        uint8_t test_context;

        /* Safety checks */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_secret_callback(NULL, s2n_test_noop_secret_handler, &test_context), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_secret_callback(conn, NULL, &test_context), S2N_ERR_NULL);

            EXPECT_EQUAL(conn->secret_cb, NULL);
            EXPECT_EQUAL(conn->secret_cb_context, NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Succeeds with NULL context */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_EQUAL(conn->secret_cb, NULL);
            EXPECT_EQUAL(conn->secret_cb_context, NULL);

            EXPECT_SUCCESS(s2n_connection_set_secret_callback(conn, s2n_test_noop_secret_handler, NULL));

            EXPECT_EQUAL(conn->secret_cb, s2n_test_noop_secret_handler);
            EXPECT_NULL(conn->secret_cb_context);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Succeeds with context */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_EQUAL(conn->secret_cb, NULL);
            EXPECT_EQUAL(conn->secret_cb_context, NULL);

            EXPECT_SUCCESS(s2n_connection_set_secret_callback(conn, s2n_test_noop_secret_handler, &test_context));

            EXPECT_EQUAL(conn->secret_cb, s2n_test_noop_secret_handler);
            EXPECT_EQUAL(conn->secret_cb_context, &test_context);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test: no API that sends/receives application data is allowed when QUIC is enabled */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_enable_quic(config));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        uint8_t buffer[10] = { 0 };
        struct iovec iovec_buffer = { .iov_base = buffer, .iov_len = sizeof(buffer) };
        s2n_blocked_status blocked_status;

        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(conn, buffer, sizeof(buffer), &blocked_status), S2N_ERR_UNSUPPORTED_WITH_QUIC);
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, buffer, sizeof(buffer), &blocked_status), S2N_ERR_UNSUPPORTED_WITH_QUIC);
        EXPECT_FAILURE_WITH_ERRNO(s2n_sendv(conn, &iovec_buffer, 1, &blocked_status), S2N_ERR_UNSUPPORTED_WITH_QUIC);
        EXPECT_FAILURE_WITH_ERRNO(s2n_sendv_with_offset(conn, &iovec_buffer, 1, 0, &blocked_status), S2N_ERR_UNSUPPORTED_WITH_QUIC);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    END_TEST();
}
