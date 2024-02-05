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

#include "tls/s2n_post_handshake.h"

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "utils/s2n_safety.h"

/* Include to get access to the handshake state machine
 * to verify we don't allow its messages post-handshake.
 */
#include "tls/s2n_handshake_io.c"

#define KEY_UPDATE_MESSAGE_SIZE sizeof(uint8_t) + /* message id */  \
        SIZEOF_UINT24 +                           /* message len */ \
        sizeof(uint8_t)                           /* message */

int s2n_key_update_write(struct s2n_blob *out);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_post_handshake_recv */
    {
        /* post_handshake_recv processes a key update requested message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_KEY_UPDATE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_REQUESTED));

            EXPECT_OK(s2n_post_handshake_recv(conn));
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* post_handshake_recv rejects an unknown post handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, -1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_REQUESTED));

            EXPECT_ERROR_WITH_ERRNO(s2n_post_handshake_recv(conn), S2N_ERR_BAD_MESSAGE);
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* post_handshake_recv processes a malformed post handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_KEY_UPDATE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_LENGTH));

            EXPECT_ERROR(s2n_post_handshake_recv(conn));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Functional test: Multiple post handshake messages can be received in the same record */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            uint8_t num_key_updates = 3;

            /* Write three key update messages in one record. We cannot call s2n_post_handshake_send
             * multiple times here because s2n only sends one handshake message per record */
            for (size_t i = 0; i < num_key_updates; i++) {
                uint8_t data[KEY_UPDATE_MESSAGE_SIZE] = { 0 };
                struct s2n_blob key_update_message = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&key_update_message, data, sizeof(data)));
                EXPECT_SUCCESS(s2n_key_update_write(&key_update_message));
                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, key_update_message.data, key_update_message.size));
            }

            EXPECT_OK(s2n_post_handshake_recv(conn));

            /* All three key update messages have been read */
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->in), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* HELLO_REQUEST messages can be received post-handshake. */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_HELLO_REQUEST));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, 0));
            EXPECT_OK(s2n_post_handshake_recv(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* No non-post handshake messages can be received.
         * This means that no handshake message that appears in the handshake state machine
         * should be allowed.
         */
        {
            /* For TLS1.2 */
            for (size_t i = 0; i < s2n_array_len(state_machine); i++) {
                if (state_machine[i].record_type != TLS_HANDSHAKE) {
                    break;
                }

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, state_machine[i].message_type));
                EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, 0));
                EXPECT_ERROR_WITH_ERRNO(s2n_post_handshake_recv(conn), S2N_ERR_BAD_MESSAGE);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* For TLS1.3 */
            for (size_t i = 0; i < s2n_array_len(tls13_state_machine); i++) {
                if (tls13_state_machine[i].record_type != TLS_HANDSHAKE) {
                    break;
                }

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, tls13_state_machine[i].message_type));
                EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, 0));
                EXPECT_ERROR_WITH_ERRNO(s2n_post_handshake_recv(conn), S2N_ERR_BAD_MESSAGE);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        };
    };

    /* post_handshake_send */
    {
        /* Post handshake messages can be sent */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_connection_set_secrets(conn));

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&output, conn));

            conn->actual_protocol_version = S2N_TLS13;
            s2n_atomic_flag_set(&conn->key_update_pending);

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_post_handshake_send(conn, &blocked));

            EXPECT_TRUE(s2n_stuffer_data_available(&output) > 0);
        };

        /* No messages sent if no post-handshake messages required */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_connection_set_secrets(conn));

            conn->actual_protocol_version = S2N_TLS13;
            s2n_atomic_flag_clear(&conn->key_update_pending);

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_post_handshake_send(conn, &blocked));

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->out), 0);
        };

        /* No messages sent if <TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_connection_set_secrets(conn));

            conn->actual_protocol_version = S2N_TLS12;
            s2n_atomic_flag_set(&conn->key_update_pending);

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_post_handshake_send(conn, &blocked));

            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->out), 0);
        };
    };

    /* Errors while processing post-handshake messages close the connection */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        DEFER_CLEANUP(struct s2n_stuffer io_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io_stuffer, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&io_stuffer, &io_stuffer, server_conn));

        /* Send just the ClientHello */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

        /* Try to read the ClientHello as a post-handshake message */
        uint8_t output_buffer[10] = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, output_buffer, sizeof(output_buffer), &blocked), S2N_ERR_BAD_MESSAGE);

        /* Error closed connection */
        EXPECT_TRUE(s2n_connection_check_io_status(server_conn, S2N_IO_CLOSED));

        /* Error triggers blinding */
        EXPECT_NOT_EQUAL(s2n_connection_get_delay(server_conn), 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    END_TEST();
}
