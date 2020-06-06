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
int s2n_check_record_limit(struct s2n_connection *conn, struct s2n_blob *sequence_number); 

int main(int argc, char **argv)
{
    S2N_BLOB_FROM_HEX(application_secret,
    "4bc28934ddd802b00f479e14a72d7725dab45d32b3b145f29"
    "e4c5b56677560eb5236b168c71c5c75aa52f3e20ee89bfb"); 

    /* The maximum record number converted to base 256 */
    uint8_t max_record_limit[S2N_TLS_SEQUENCE_NUM_LEN] = {0, 0, 0, 0, 1, 106, 9, 229};

    BEGIN_TEST();
    /* s2n_key_update_write */
    {
        /* Tests s2n_key_update_write writes as expected */
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
    }
    /* s2n_key_update_recv */
    {
        /* Key update message received contains invalid key update request */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            /* Write invalid value for key update request type */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, -1));

            EXPECT_FAILURE_WITH_ERRNO(s2n_key_update_recv(conn, &input), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Server receives valid key update request */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            memcpy_check(server_conn->secure.client_app_secret, application_secret.data, application_secret.size);

            server_conn->secure.client_sequence_number[0] = 1; 
            /* Write the key update request to the correct stuffer */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_KEY_UPDATE_NOT_REQUESTED));

            EXPECT_SUCCESS(s2n_key_update_recv(server_conn, &input));
            EXPECT_EQUAL(server_conn->secure.client_sequence_number[0], 0);
            EXPECT_EQUAL(server_conn->key_update_pending, S2N_KEY_UPDATE_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Client receives valid key update request */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            memcpy_check(client_conn->secure.server_app_secret, application_secret.data, application_secret.size);

            client_conn->secure.server_sequence_number[0] = 1; 
            /* Write the key update request to the correct stuffer */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_KEY_UPDATE_NOT_REQUESTED));

            EXPECT_SUCCESS(s2n_key_update_recv(client_conn, &input));
            EXPECT_EQUAL(client_conn->secure.server_sequence_number[0], 0);
            EXPECT_EQUAL(client_conn->key_update_pending, S2N_KEY_UPDATE_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }
        
    }
    /* s2n_key_update_send */
    {   
        /* Key update has been requested */
        {
            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            memcpy_check(client_conn->secure.client_app_secret, application_secret.data, application_secret.size);
            uint8_t zeroed_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = {0};
   
            client_conn->key_update_pending = true;

            EXPECT_SUCCESS(s2n_key_update_send(client_conn));

            EXPECT_EQUAL(client_conn->key_update_pending, false);
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure.client_sequence_number, zeroed_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }

        /* Key update is triggered by encryption limits */
        {
            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            memcpy_check(client_conn->secure.client_app_secret, application_secret.data, application_secret.size);
            uint8_t zeroed_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = {0};

            client_conn->key_update_pending = false;

            for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
                client_conn->secure.client_sequence_number[i] = max_record_limit[i];
            }
            
            EXPECT_SUCCESS(s2n_key_update_send(client_conn));

            EXPECT_EQUAL(client_conn->key_update_pending, false);
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure.client_sequence_number, zeroed_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);
            
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        } 
        /* Key update is not triggered */
        {
            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            memcpy_check(client_conn->secure.client_app_secret, application_secret.data, application_secret.size);
            uint8_t expected_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = {0};

            client_conn->secure.client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN - 1] = 1; 
            expected_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN - 1] = 1;
            client_conn->key_update_pending = false;

            EXPECT_SUCCESS(s2n_key_update_send(client_conn));

            EXPECT_EQUAL(client_conn->key_update_pending, false);
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure.client_sequence_number, expected_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);
            
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        } 
    }
    /* s2n_check_record_limit */
    {
        /* Key update NOT triggered when encrypted bytes exactly matches encryption limit */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            struct s2n_blob sequence_number = {0};
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, conn->secure.server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
            
            EXPECT_EQUAL(conn->key_update_pending, false);

            for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
                conn->secure.server_sequence_number[i] = max_record_limit[i];
            }
            /* Change sequence number to be exactly record limit - 1 */
            conn->secure.server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN - 1] -= 1; 

            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            
            EXPECT_EQUAL(conn->key_update_pending, false);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* Key update is triggered when record limit exceeds encryption limit */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            struct s2n_blob sequence_number = {0};
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, conn->secure.server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
            
            EXPECT_EQUAL(conn->key_update_pending, false);

            for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
                conn->secure.server_sequence_number[i] = max_record_limit[i];
            }

            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));

            EXPECT_EQUAL(conn->key_update_pending, true);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* Key update NOT triggered when encrypted bytes are below encryption limit */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            struct s2n_blob sequence_number = {0};
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, conn->secure.server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

            EXPECT_EQUAL(conn->key_update_pending, false);
            /* set record number to below encryption limit */
            conn->secure.server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN - 1] = 1;

            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_EQUAL(conn->key_update_pending, false);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* Key update NOT triggered when cipher suite does not have encryption limit */
        /* Skip test if libcrypto doesn't support the cipher */
        if (s2n_chacha20_poly1305.is_available()) {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            /* Setting cipher suite to suite that does not have an encryption limit */
            conn->secure.cipher_suite = &s2n_tls13_chacha20_poly1305_sha256;
            struct s2n_blob sequence_number = {0};
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, conn->secure.server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

            EXPECT_EQUAL(conn->key_update_pending, 0);

            for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
                conn->secure.server_sequence_number[i] = UINT8_MAX;
            }

            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));

            EXPECT_EQUAL(conn->key_update_pending, false);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }

        /* Key update NOT triggered when cipher suite does not have encryption limit and
         * when record limit exactly equals UINT64_MAX
         */
        if (s2n_chacha20_poly1305.is_available()) {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            /* Setting cipher suite to suite that does not have an encryption limit */
            conn->secure.cipher_suite = &s2n_tls13_chacha20_poly1305_sha256;
            struct s2n_blob sequence_number = {0};
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, conn->secure.server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
            
            EXPECT_EQUAL(conn->key_update_pending, 0);

            for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
                conn->secure.server_sequence_number[i] = UINT8_MAX;
            }
            conn->secure.server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN - 1] -= 1;
            
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));

            EXPECT_EQUAL(conn->key_update_pending, false);

            EXPECT_SUCCESS(s2n_connection_free(conn)); 
        }
    }

    END_TEST();
}
