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

#include "tls/s2n_key_update.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_cipher_suites.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_key_update_write(struct s2n_blob *out);

int main(int argc, char **argv)
{

    BEGIN_TEST();

     /* This test checks the s2n_key_update_write function correctly writes an update_not_requested message as
      * s2n does not currently require peers to update their keys.
      */
    {
        uint8_t key_update_data[S2N_KEY_UPDATE_MESSAGE_SIZE];
        struct s2n_blob key_update_blob = {0};
        struct s2n_stuffer key_update_stuffer = {0};
        EXPECT_SUCCESS(s2n_blob_init(&key_update_blob, key_update_data, sizeof(key_update_data)));
        EXPECT_SUCCESS(s2n_stuffer_init(&key_update_stuffer, &key_update_blob));

        /* Write key update message */
        EXPECT_SUCCESS(s2n_key_update_write(&key_update_blob));

        /* Move stuffer write cursor to correct position */
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_update_stuffer, S2N_KEY_UPDATE_MESSAGE_SIZE));

        uint8_t post_handshake_id;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&key_update_stuffer, &post_handshake_id));
        EXPECT_EQUAL(post_handshake_id, TLS_KEY_UPDATE);

        uint32_t request_length;
        EXPECT_SUCCESS(s2n_stuffer_read_uint24(&key_update_stuffer, &request_length));
        EXPECT_EQUAL(request_length, S2N_KEY_UPDATE_LENGTH);

        uint8_t key_update_request;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&key_update_stuffer, &key_update_request));
        EXPECT_EQUAL(key_update_request, S2N_KEY_UPDATE_NOT_REQUESTED);
    }

    /* This test checks in the s2n_check_key_limits method that a key update is triggered once the maximum number of 
     * bytes have been encrypted by an application key.
     */
    {
        struct s2n_connection *conn;
        uint8_t data_size = 1;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        EXPECT_EQUAL(conn->key_update_pending, 0);
        conn->encrypted_bytes_out = S2N_TLS13_AES_GCM_MAXIMUM_BYTES_TO_ENCRYPT;

        EXPECT_SUCCESS(s2n_check_key_limits(conn, data_size));
        EXPECT_EQUAL(conn->key_update_pending, 1);

        EXPECT_SUCCESS(s2n_connection_free(conn)); 
    }

    /* This test checks that a key update is triggered in the s2n_check_key_limits function if more than the 
     * maximum number of bytes have been encrypted.
     */
    {
        struct s2n_connection *conn;
        uint8_t data_size = 1;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        EXPECT_EQUAL(conn->key_update_pending, 0);
        conn->encrypted_bytes_out = S2N_TLS13_AES_GCM_MAXIMUM_BYTES_TO_ENCRYPT + 1;

        EXPECT_SUCCESS(s2n_check_key_limits(conn, data_size));
        EXPECT_EQUAL(conn->key_update_pending, 1);

        EXPECT_SUCCESS(s2n_connection_free(conn)); 
    }

    /* This test checks that a key update is not triggered in the s2n_check_key_limits function if the 
     * maximum number of bytes have not been encrypted by an application key.
     */
    {
        struct s2n_connection *conn;
        uint8_t data_size = 1;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        
        EXPECT_EQUAL(conn->key_update_pending, 0);
        conn->encrypted_bytes_out = S2N_TLS13_AES_GCM_MAXIMUM_BYTES_TO_ENCRYPT - 5;

        EXPECT_SUCCESS(s2n_check_key_limits(conn, data_size));
        EXPECT_EQUAL(conn->key_update_pending, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn)); 
    }

    /* Test s2n_key_update_recv function when it receives an invalid value for the key update request
     * (e.g. neither update_requested nor update_not_requested).
     * */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        /* Write invalid value for key update request type */
        GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, 3));
        EXPECT_FAILURE_WITH_ERRNO(s2n_key_update_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}

