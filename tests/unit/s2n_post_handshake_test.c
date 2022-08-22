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

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_post_handshake.h"
#include "utils/s2n_safety.h"

/* Include to get access to the handshake state machine
 * to verify we don't allow its messages post-handshake.
 */
#include "tls/s2n_handshake_io.c"

#define KEY_UPDATE_MESSAGE_SIZE sizeof(uint8_t) + /* message id */  \
                                SIZEOF_UINT24   + /* message len */ \
                                sizeof(uint8_t)   /* message */

bool s2n_post_handshake_is_known(uint8_t message_type);
bool s2n_post_handshake_is_valid_to_recv(s2n_mode mode, uint8_t message_type);
int s2n_key_update_write(struct s2n_blob *out);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_post_handshake_is_known
     *
     * Unfortunately, s2n_post_handshake_is_known relies on a hardcoded list
     * to identify known handshake messages not allowed post-handshake.
     *
     * This test verifies that list is correct and enforces that we keep it up to date.
     */
    {
        /* We rely on record type being set to identify invalid state machine entries.
         * Verify that assumption.
         */
        EXPECT_NOT_EQUAL(TLS_HANDSHAKE, 0);

        for (size_t i = 0; i < UINT8_MAX; i++) {
            bool is_handshake_message = false;
            for (size_t j = 0; j < s2n_array_len(state_machine); j++) {
                if (state_machine[j].record_type != TLS_HANDSHAKE) {
                    continue;
                }
                if (state_machine[j].message_type != i) {
                    continue;
                }
                is_handshake_message = true;
                break;
            }
            for (size_t j = 0; j < s2n_array_len(tls13_state_machine); j++) {
                if (tls13_state_machine[j].record_type != TLS_HANDSHAKE) {
                    continue;
                }
                if (tls13_state_machine[j].message_type != i) {
                    continue;
                }
                is_handshake_message = true;
                break;
            }

            bool is_valid_to_receive = s2n_post_handshake_is_valid_to_recv(S2N_CLIENT, i)
                    || s2n_post_handshake_is_valid_to_recv(S2N_SERVER, i);
            bool is_post_handshake_message = is_valid_to_receive && s2n_post_handshake_is_known(i);

            /* We should have no overlap between handshake and post-handshake messages.
             *
             * The only exception is TLS_SERVER_NEW_SESSION_TICKET, which is a handshake
             * message in TLS1.2 and a post-handshake message in TLS1.3.
             */
            if (i != TLS_SERVER_NEW_SESSION_TICKET) {
                EXPECT_FALSE(is_handshake_message && is_post_handshake_message);
            }

            /* All handshake messages must be included in the list in s2n_post_handshake_is_known */
            bool is_known = is_handshake_message || is_post_handshake_message;
            EXPECT_EQUAL(is_known, s2n_post_handshake_is_known(i));
        }
    }

    /* s2n_post_handshake_recv */
    {   
        /* post_handshake_recv processes a key update requested message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(conn->key_update_pending);

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_KEY_UPDATE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_REQUESTED));

            EXPECT_OK(s2n_post_handshake_recv(conn));
            EXPECT_TRUE(conn->key_update_pending);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* post_handshake_recv processes an unknown post handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(conn->key_update_pending);

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, -1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_REQUESTED));

            EXPECT_OK(s2n_post_handshake_recv(conn));
            EXPECT_FALSE(conn->key_update_pending);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* post_handshake_recv processes a malformed post handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(conn->key_update_pending);

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_KEY_UPDATE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_LENGTH));

            EXPECT_ERROR(s2n_post_handshake_recv(conn));
            EXPECT_FALSE(conn->key_update_pending);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

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
        }

        /* HELLO_REQUEST messages can be received post-handshake. */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_HELLO_REQUEST));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, 0));
            EXPECT_OK(s2n_post_handshake_recv(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

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
        }
    }

    /* post_handshake_send */
    {
        /* Post handshake message can be sent */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;    
            s2n_blocked_status blocked;

            EXPECT_SUCCESS(s2n_post_handshake_send(conn, &blocked));
            EXPECT_TRUE(s2n_stuffer_data_available(&conn->out) == 0);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }
    }

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
        EXPECT_TRUE(server_conn->closed);

        /* Error triggers blinding */
        EXPECT_NOT_EQUAL(s2n_connection_get_delay(server_conn), 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    END_TEST();
}
