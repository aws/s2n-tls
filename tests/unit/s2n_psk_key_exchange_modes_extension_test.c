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
#include "tls/extensions/s2n_psk_key_exchange_modes.h"

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
    };

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

            EXPECT_SUCCESS(s2n_extension_recv(&s2n_psk_key_exchange_modes_extension, conn, &out));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

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
        };

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
        };

        /* Receives list of supported and unsupported psk key exchange modes */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, PSK_KEY_EXCHANGE_MODE_SIZE * 2));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, TLS_PSK_KE_MODE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, TLS_PSK_DHE_KE_MODE));

            EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(conn, &out));

            /* s2n chooses the only currently supported psk key exchange mode */
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_DHE_KE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

        /* Server receives GREASE values.
         *
         *= https://www.rfc-editor.org/rfc/rfc8701#section-3.1
         *= type=test
         *# A client MAY select one or more GREASE PskKeyExchangeMode values
         *# and advertise them in the "psk_key_exchange_modes" extension, if
         *# sent.
         *
         *= https://www.rfc-editor.org/rfc/rfc8701#section-3.2
         *= type=test
         *# When processing a ClientHello, servers MUST NOT treat GREASE values
         *# differently from any unknown value.  Servers MUST NOT negotiate any
         *# GREASE value when offered in a ClientHello.  Servers MUST correctly
         *# ignore unknown values in a ClientHello and attempt to negotiate with
         *# one of the remaining parameters.
         **/
        {
            DEFER_CLEANUP(struct s2n_stuffer extension = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));

            struct s2n_stuffer_reservation modes_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint8(&extension, &modes_size));

            /*
             *= https://www.rfc-editor.org/rfc/rfc8701#section-2
             *= type=test
             *# The following values are reserved as GREASE values for
             *# PskKeyExchangeModes:
             *#
             *#    0x0B
             *#
             *#    0x2A
             *#
             *#    0x49
             *#
             *#    0x68
             *#
             *#    0x87
             *#
             *#    0xA6
             *#
             *#    0xC5
             *#
             *#    0xE4
             */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x0B));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x2A));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x49));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x68));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0x87));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0xA6));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0xC5));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, 0xE4));

            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&modes_size));

            /* No valid non-GREASE option */
            {
                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(conn, &extension));
                EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_stuffer_reread(&extension));
            };

            /* Valid non-GREASE option */
            {
                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                conn->actual_protocol_version = S2N_TLS13;

                /* Add the valid option and rewrite size */
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&extension, TLS_PSK_DHE_KE_MODE));
                EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&modes_size));

                EXPECT_SUCCESS(s2n_psk_key_exchange_modes_extension.recv(conn, &extension));
                EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_DHE_KE);

                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_stuffer_reread(&extension));
            };
        };
    };

    /* Test: s2n_psk_key_exchange_modes_should_send */
    {
        /* When neither resumption nor PSKs are enabled, the extension should not be sent. */
        {
            DEFER_CLEANUP(struct s2n_config *no_resumption_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(no_resumption_config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(no_resumption_config, false));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, no_resumption_config));

            EXPECT_FALSE(s2n_psk_key_exchange_modes_extension.should_send(conn));
        };

        /* When session resumption is enabled, the extension should be sent. */
        {
            DEFER_CLEANUP(struct s2n_config *resumption_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(resumption_config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(resumption_config, true));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, resumption_config));

            EXPECT_TRUE(s2n_psk_key_exchange_modes_extension.should_send(conn));
        };

        /* When a client is using out-of-band PSKs, the extension should be sent. */
        {
            DEFER_CLEANUP(struct s2n_config *psk_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(psk_config);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(psk_config, false));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, psk_config));

            DEFER_CLEANUP(struct s2n_psk *psk = s2n_test_psk_new(conn), s2n_psk_free);
            EXPECT_SUCCESS(s2n_connection_append_psk(conn, psk));

            EXPECT_TRUE(s2n_psk_key_exchange_modes_extension.should_send(conn));
        };
    };

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
    };

    END_TEST();
}
