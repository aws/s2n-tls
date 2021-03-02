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

#define KEY_UPDATE_MESSAGE_SIZE sizeof(uint8_t) + /* message id */  \
                                SIZEOF_UINT24   + /* message len */ \
                                sizeof(uint8_t)   /* message */

int s2n_key_update_write(struct s2n_blob *out);

int main(int argc, char **argv)
{

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());
    /* s2n_post_handshake_recv */
    {   
        /* post_handshake_recv processes a key update requested message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(conn->key_update_pending);

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_KEY_UPDATE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_REQUESTED));

            EXPECT_SUCCESS(s2n_post_handshake_recv(conn));
            EXPECT_TRUE(conn->key_update_pending);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* post_handshake_recv processes an unknown post handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(conn->key_update_pending);

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, -1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_REQUESTED));

            EXPECT_SUCCESS(s2n_post_handshake_recv(conn));
            EXPECT_FALSE(conn->key_update_pending);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* post_handshake_recv processes a malformed post handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_FALSE(conn->key_update_pending);

            /* Write key update requested to conn->in */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_KEY_UPDATE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_LENGTH));

            EXPECT_FAILURE(s2n_post_handshake_recv(conn));
            EXPECT_FALSE(conn->key_update_pending);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* post_handshake_recv will error when protocol version is not TLS1.3 */ 
        {   
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            EXPECT_FAILURE_WITH_ERRNO(s2n_post_handshake_recv(conn), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* Functional test: Multiple post handshake messages can be received in the same record */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
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

            EXPECT_SUCCESS(s2n_post_handshake_recv(conn));

            /* All three key update messages have been read */
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->in), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* post_handshake_send */
    {
        /* Post handshake message can be sent */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;    
            s2n_blocked_status blocked;

            EXPECT_SUCCESS(s2n_post_handshake_send(conn, &blocked));
            EXPECT_TRUE(s2n_stuffer_data_available(&conn->out) == 0);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }
    }
    END_TEST();
}


