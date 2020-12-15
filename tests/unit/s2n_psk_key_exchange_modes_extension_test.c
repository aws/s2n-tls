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
#include "testlib/s2n_testlib.h"

#include "tls/s2n_psk.h"

/* Include source to test static functions */
#include "tls/extensions/s2n_psk_key_exchange_modes.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_psk_key_exchange_modes_send */
    {
        struct s2n_stuffer out = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.send(conn, &out));

        uint8_t psk_ke_modes_size = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &psk_ke_modes_size));
        EXPECT_EQUAL(psk_ke_modes_size, PSK_KEY_EXCHANGE_MODE_SIZE);

        uint8_t psk_ke_mode = S2N_PSK_KE_UNKNOWN;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &psk_ke_mode));
        EXPECT_EQUAL(psk_ke_mode, TLS_PSK_DHE_KE_MODE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&out));
    }

    /* Test: s2n_psk_key_exchange_modes_recv */
    {   
        /* Receive an extension when running TLS1.2 */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            /* Incorrect protocol version */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, PSK_KEY_EXCHANGE_MODE_SIZE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, TLS_PSK_DHE_KE_MODE));

            EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(conn, &out));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* Length of extension is greater than contents of extension */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            conn->actual_protocol_version = S2N_TLS13;

            /* Incorrect length */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, PSK_KEY_EXCHANGE_MODE_SIZE + 1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, TLS_PSK_DHE_KE_MODE));

            EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(conn, &out));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* Receives valid psk_ke mode */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, PSK_KEY_EXCHANGE_MODE_SIZE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, TLS_PSK_KE_MODE));

            EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(conn, &out));

            /* s2n currently does not support the psk_ke mode */
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* Receives list of supported and unsupported psk key exchange modes */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, PSK_KEY_EXCHANGE_MODE_SIZE + 1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, TLS_PSK_KE_MODE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, TLS_PSK_DHE_KE_MODE));

            EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(conn, &out));

            /* s2n chooses the only currently supported psk key exchange mode */
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_DHE_KE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }
    }

    /* Functional test */
    {
        struct s2n_stuffer out = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_EQUAL(server_conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

        server_conn->actual_protocol_version = S2N_TLS13;
        client_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.send(client_conn, &out));
        EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(server_conn, &out));

        EXPECT_EQUAL(server_conn->psk_params.psk_ke_mode, S2N_PSK_DHE_KE);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&out));
    }

    END_TEST();
}
