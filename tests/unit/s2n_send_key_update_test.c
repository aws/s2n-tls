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

#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_record.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls13_handshake.h"

static int s2n_test_init_encryption(struct s2n_connection *conn)
{   
    struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    conn->server->cipher_suite = cipher_suite;
    conn->client->cipher_suite = cipher_suite;
 
    /* Just some data that's the right length */
    S2N_BLOB_FROM_HEX(key, "0123456789abcdef0123456789abcdef");
    S2N_BLOB_FROM_HEX(iv, "0123456789abcdef01234567");
    S2N_BLOB_FROM_HEX(application_secret,
    "4bc28934ddd802b00f479e14a72d7725dab45d32b3b145f29"
    "e4c5b56677560eb5236b168c71c5c75aa52f3e20ee89bfb"); 
 
    struct s2n_session_key *server_session_key = &conn->server->server_key;
    struct s2n_session_key *client_session_key = &conn->server->server_key;
    uint8_t *server_implicit_iv = conn->server->server_implicit_iv;
    uint8_t *client_implicit_iv = conn->client->client_implicit_iv;
 
    /* Initialize record algorithm */
    GUARD(cipher_suite->record_alg->cipher->init(server_session_key));
    GUARD(cipher_suite->record_alg->cipher->init(client_session_key));
    GUARD(cipher_suite->record_alg->cipher->set_encryption_key(server_session_key, &key));
    GUARD(cipher_suite->record_alg->cipher->set_encryption_key(client_session_key, &key));
    GUARD(cipher_suite->record_alg->cipher->set_decryption_key(server_session_key, &key));
    GUARD(cipher_suite->record_alg->cipher->set_decryption_key(client_session_key, &key));

    /* Initialized secrets */
    memcpy_check(conn->secure.server_app_secret, application_secret.data, application_secret.size);
    memcpy_check(conn->secure.client_app_secret, application_secret.data, application_secret.size);
 
    /* Copy iv bytes from input data */
    memcpy_check(server_implicit_iv, iv.data, iv.size);
    memcpy_check(client_implicit_iv, iv.data, iv.size);
 
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{   
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

    /* s2n_send sends key update if necessary */
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        server_conn->actual_protocol_version = S2N_TLS13;
        client_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        EXPECT_SUCCESS(s2n_test_init_encryption(server_conn));
        EXPECT_SUCCESS(s2n_test_init_encryption(client_conn));

        DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer output, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
                                        
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client_conn));
        
        /* Mimic key update send conditions */
        server_conn->encrypted_bytes_out = S2N_TLS13_AES_GCM_MAXIMUM_BYTES_TO_ENCRYPT;

        /* Next message to send will trigger key update message*/
        s2n_blocked_status blocked;
        char message[] = "sent message";
        EXPECT_SUCCESS(s2n_send(server_conn, message, sizeof(message), &blocked));
        
        /* Verify key update happened */
        EXPECT_BYTEARRAY_NOT_EQUAL(server_conn->secure.server_app_secret, client_conn->secure.server_app_secret, S2N_TLS13_SECRET_MAX_LEN);

        /* Verify encrypted_bytes_out is being counted correctly */
        uint8_t expected_encrypted_bytes_out = sizeof(message) +
            server_conn->secure.cipher_suite->record_alg->cipher->io.aead.tag_size + TLS13_CONTENT_TYPE_LENGTH;
        EXPECT_EQUAL(server_conn->encrypted_bytes_out, expected_encrypted_bytes_out);
        
        /* Receive keyupdate message */
        uint8_t data[100];
        EXPECT_SUCCESS(s2n_recv(client_conn, data, sizeof(message), &blocked));
        EXPECT_BYTEARRAY_EQUAL(data, message, sizeof(message));
        EXPECT_BYTEARRAY_EQUAL(client_conn->secure.server_app_secret, server_conn->secure.server_app_secret, S2N_TLS13_SECRET_MAX_LEN);
        
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    END_TEST();
}


