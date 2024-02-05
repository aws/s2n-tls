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

#include "crypto/s2n_rsa_signing.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_key_log.h"

static int s2n_test_key_log_cb(void *context, struct s2n_connection *conn,
        uint8_t *logline, size_t len)
{
    struct s2n_stuffer *stuffer = (struct s2n_stuffer *) context;
    POSIX_GUARD(s2n_stuffer_write_bytes(stuffer, logline, len));
    POSIX_GUARD(s2n_stuffer_write_uint8(stuffer, '\n'));

    return S2N_SUCCESS;
}

S2N_RESULT s2n_test_check_tls12(struct s2n_stuffer *stuffer)
{
    size_t len = s2n_stuffer_data_available(stuffer);
    RESULT_ENSURE_GT(len, 0);
    char *out = (char *) s2n_stuffer_raw_read(stuffer, len);
    RESULT_ENSURE_REF(out);
    /**
     * rather than writing a full parser, we'll just make sure it at least
     * wrote the labels we would expect for TLS 1.2
     */
    RESULT_ENSURE_REF(strstr(out, "CLIENT_RANDOM "));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_check_tls13(struct s2n_stuffer *stuffer)
{
    size_t len = s2n_stuffer_data_available(stuffer);
    RESULT_ENSURE_GT(len, 0);
    char *out = (char *) s2n_stuffer_raw_read(stuffer, len);
    RESULT_ENSURE_REF(out);
    /**
     * rather than writing a full parser, we'll just make sure it at least
     * wrote the labels we would expect for TLS 1.3
     */
    RESULT_ENSURE_REF(strstr(out, "CLIENT_HANDSHAKE_TRAFFIC_SECRET "));
    RESULT_ENSURE_REF(strstr(out, "SERVER_HANDSHAKE_TRAFFIC_SECRET "));
    RESULT_ENSURE_REF(strstr(out, "CLIENT_TRAFFIC_SECRET_0 "));
    RESULT_ENSURE_REF(strstr(out, "SERVER_TRAFFIC_SECRET_0 "));
    RESULT_ENSURE_REF(strstr(out, "EXPORTER_SECRET "));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* TLS 1.2 */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
        DEFER_CLEANUP(struct s2n_stuffer client_key_log, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_key_log, 1024));
        EXPECT_SUCCESS(s2n_config_set_key_log_cb(client_config, s2n_test_key_log_cb, &client_key_log));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_config *server_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        DEFER_CLEANUP(struct s2n_stuffer server_key_log, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_key_log, 1024));
        EXPECT_SUCCESS(s2n_config_set_key_log_cb(server_config, s2n_test_key_log_cb, &server_key_log));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Do handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_OK(s2n_test_check_tls12(&client_key_log));
        EXPECT_OK(s2n_test_check_tls12(&server_key_log));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    };

    /* TLS 1.3 */
    if (s2n_is_tls13_fully_supported()) {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *client_config;
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
        DEFER_CLEANUP(struct s2n_stuffer client_key_log, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_key_log, 1024));
        EXPECT_SUCCESS(s2n_config_set_key_log_cb(client_config, s2n_test_key_log_cb, &client_key_log));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_config *server_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        DEFER_CLEANUP(struct s2n_stuffer server_key_log, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_key_log, 1024));
        EXPECT_SUCCESS(s2n_config_set_key_log_cb(server_config, s2n_test_key_log_cb, &server_key_log));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Do handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_OK(s2n_test_check_tls13(&client_key_log));
        EXPECT_OK(s2n_test_check_tls13(&server_key_log));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /* Hex encoding function inverse pair */
    {
        uint8_t bytes[256] = { 0 };

        for (size_t idx = 0; idx < sizeof(bytes); idx++) {
            bytes[idx] = (uint8_t) idx;
        }

        DEFER_CLEANUP(struct s2n_stuffer encoded, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&encoded, sizeof(bytes) * 2));
        EXPECT_OK(s2n_key_log_hex_encode(&encoded, bytes, sizeof(bytes)));

        DEFER_CLEANUP(struct s2n_stuffer decoded, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&decoded, sizeof(bytes)));
        EXPECT_SUCCESS(s2n_stuffer_read_hex(&encoded, &decoded, sizeof(bytes)));

        uint8_t *out = s2n_stuffer_raw_read(&decoded, s2n_stuffer_data_available(&decoded));
        EXPECT_NOT_NULL(out);

        EXPECT_EQUAL(memcmp(bytes, out, sizeof(bytes)), 0);
    };

    END_TEST();
}
