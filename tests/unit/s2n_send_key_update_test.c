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

#include <stdint.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"

int s2n_key_update_write(struct s2n_blob *out);

static int s2n_test_init_encryption(struct s2n_connection *conn)
{
    struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    conn->server->cipher_suite = cipher_suite;
    conn->client->cipher_suite = cipher_suite;
    conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

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
    POSIX_GUARD(cipher_suite->record_alg->cipher->init(server_session_key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->init(client_session_key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_encryption_key(server_session_key, &key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_encryption_key(client_session_key, &key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_decryption_key(server_session_key, &key));
    POSIX_GUARD(cipher_suite->record_alg->cipher->set_decryption_key(client_session_key, &key));

    /* Initialized secrets */
    POSIX_CHECKED_MEMCPY(conn->secrets.version.tls13.server_app_secret, application_secret.data, application_secret.size);
    POSIX_CHECKED_MEMCPY(conn->secrets.version.tls13.client_app_secret, application_secret.data, application_secret.size);

    /* Copy iv bytes from input data */
    POSIX_CHECKED_MEMCPY(server_implicit_iv, iv.data, iv.size);
    POSIX_CHECKED_MEMCPY(client_implicit_iv, iv.data, iv.size);

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* The maximum record number converted to base 256 */
    uint8_t max_record_limit[S2N_TLS_SEQUENCE_NUM_LEN] = { 0, 0, 0, 0, 1, 106, 9, 229 };

    /* s2n_send sends key update if necessary */
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        server_conn->actual_protocol_version = S2N_TLS13;
        client_conn->actual_protocol_version = S2N_TLS13;

        uint8_t zero_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };

        EXPECT_SUCCESS(s2n_test_init_encryption(server_conn));
        EXPECT_SUCCESS(s2n_test_init_encryption(client_conn));

        DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer output, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client_conn));

        /* Mimic key update send conditions */
        for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
            server_conn->secure->server_sequence_number[i] = max_record_limit[i];
        }

        /* Next message to send will trigger key update message*/
        s2n_blocked_status blocked;
        char message[] = "sent message";
        EXPECT_SUCCESS(s2n_send(server_conn, message, sizeof(message), &blocked));

        /* Verify key update happened */
        EXPECT_BYTEARRAY_NOT_EQUAL(server_conn->secrets.version.tls13.server_app_secret, client_conn->secrets.version.tls13.server_app_secret, S2N_TLS13_SECRET_MAX_LEN);
        EXPECT_BYTEARRAY_EQUAL(server_conn->secure->server_sequence_number, zero_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);

        /* Receive keyupdate message */
        uint8_t data[100];
        EXPECT_SUCCESS(s2n_recv(client_conn, data, sizeof(message), &blocked));
        EXPECT_BYTEARRAY_EQUAL(data, message, sizeof(message));
        EXPECT_BYTEARRAY_EQUAL(client_conn->secrets.version.tls13.server_app_secret, server_conn->secrets.version.tls13.server_app_secret, S2N_TLS13_SECRET_MAX_LEN);
        EXPECT_BYTEARRAY_EQUAL(client_conn->secure->server_sequence_number, zero_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* TLS 1.2 Server that receives TLS 1.3 KeyUpdate from Client should close connection */
    {
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());

        char *cert_chain;
        char *private_key;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(setenv("S2N_DONT_MLOCK", "1", 0));
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        struct s2n_cert_chain_and_key *chain_and_key;
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(client_config, 0));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        client_conn->actual_protocol_version = S2N_TLS12;
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Force Client to send a TLS 1.3 KeyUpdate Message over TLS 1.2 connection */
        uint8_t key_update_data[S2N_KEY_UPDATE_MESSAGE_SIZE] = { 0 };
        struct s2n_blob key_update_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&key_update_blob, key_update_data, sizeof(key_update_data)));
        EXPECT_SUCCESS(s2n_key_update_write(&key_update_blob));
        EXPECT_OK(s2n_record_write(client_conn, TLS_HANDSHAKE, &key_update_blob));
        EXPECT_SUCCESS(s2n_flush(client_conn, &blocked));

        /* Attempt to recv on Server conn, see KeyUpdate Message, and confirm connection is closed. */
        uint8_t server_message[128];
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, server_message, sizeof(server_message), &blocked), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        free(cert_chain);
        free(private_key);
    };

    END_TEST();
}
