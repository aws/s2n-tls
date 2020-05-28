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

int s2n_key_update_write(struct s2n_blob *out);

int main(int argc, char **argv)
{

    BEGIN_TEST();

    /* This test checks that the post_handshake_recv function correctly processes a post_handshake keyupdate message. */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
       
        /* Write key update to conn->in */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, TLS_KEY_UPDATE));
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_NOT_REQUESTED));

        EXPECT_SUCCESS(s2n_post_handshake_recv(conn));

        /* Check that handshake.io has been wiped */
        EXPECT_EQUAL(conn->handshake.io.read_cursor, 0);
        EXPECT_EQUAL(conn->handshake.io.write_cursor, 0);
        EXPECT_SUCCESS(s2n_connection_free(conn)); 
    }

    /* This test checks that the post_handshake_recv function correctly deals with a post_handshake message that is
     * not a keyupdate message. Currently the correct functionality is to ignore the message.
     */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
               
        /* Handshake message id is not a KeyUpdate */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&conn->in, S2N_KEY_UPDATE_LENGTH));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&conn->in, S2N_KEY_UPDATE_NOT_REQUESTED));

        EXPECT_SUCCESS(s2n_post_handshake_recv(conn));

        /* Check that handshake.io has been wiped*/
        EXPECT_EQUAL(conn->handshake.io.read_cursor, 0);
        EXPECT_EQUAL(conn->handshake.io.write_cursor, 0);
        EXPECT_SUCCESS(s2n_connection_free(conn)); 
    }

    /* This test checks that the post_handshake_recv function correctly errors out when a keyupdate message is received
     * on a connection that is not TLS1.3.
     */
    {   
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS12;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        EXPECT_FAILURE_WITH_ERRNO(s2n_post_handshake_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(conn)); 
    }

    END_TEST();
}


