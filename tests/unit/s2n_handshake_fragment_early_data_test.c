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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_blocking_io_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

#define S2N_FRAG_LEN_SMALLER_THAN_CH 150

static struct s2n_config *s2n_test_config_new(struct s2n_cert_chain_and_key *chain_and_key)
{
    struct s2n_config *config = s2n_config_new();
    PTR_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "default_tls13"));
    PTR_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    PTR_GUARD_POSIX(s2n_config_disable_x509_verification(config));
    return config;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    const uint32_t fragment_sizes[] = {
        1,
        2,
        TLS_HANDSHAKE_HEADER_LENGTH,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
        S2N_FRAG_LEN_SMALLER_THAN_CH,
        S2N_DEFAULT_FRAGMENT_LENGTH,
    };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    /* Test: handshake with early data and fragmented messages */
    for (size_t i = 0; i < s2n_array_len(fragment_sizes); i++) {
        uint32_t server_fragment_size = fragment_sizes[i];
        uint32_t client_fragment_size = fragment_sizes[i] + 1;

        uint8_t early_data_bytes[] = "hello world";
        struct s2n_blob early_data = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&early_data, early_data_bytes, sizeof(early_data_bytes)));

        DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain_and_key),
                s2n_config_ptr_free);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, early_data.size, &s2n_tls13_aes_256_gcm_sha384));
        server_conn->max_outgoing_fragment_length = server_fragment_size;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, early_data.size, &s2n_tls13_aes_256_gcm_sha384));
        client_conn->max_outgoing_fragment_length = client_fragment_size;

        struct s2n_blocking_io_wrapper_pair io_wrapper = { 0 };
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_connections_set_blocking_io_pair(&io_wrapper, client_conn, server_conn, &io_pair));

        uint8_t recv_buffer[sizeof(early_data_bytes)] = { 0 };
        struct s2n_blob early_data_received = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&early_data_received, recv_buffer, sizeof(recv_buffer)));

        EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_test_server_and_client_with_early_data(server_conn, client_conn,
                                        &early_data, &early_data_received),
                S2N_ERR_IO_BLOCKED);

        /* All early data received */
        EXPECT_TRUE(WITH_EARLY_DATA(server_conn));
        EXPECT_TRUE(WITH_EARLY_DATA(client_conn));
        S2N_BLOB_EXPECT_EQUAL(early_data, early_data_received);

        while (s2n_negotiate_test_server_and_client(server_conn, client_conn) < S2N_SUCCESS) {
            POSIX_ENSURE(s2n_errno, S2N_ERR_IO_BLOCKED);
        }

        /* Handshake completed */
        EXPECT_TRUE(IS_NEGOTIATED(server_conn));
        EXPECT_TRUE(IS_NEGOTIATED(client_conn));
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
    }

    END_TEST();
}
