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

#include "tls/s2n_ktls.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_random.h"

#if defined(S2N_KTLS_SUPPORTED)
S2N_RESULT s2n_ktls_init_aes128_gcm_crypto_info(struct s2n_connection *conn, s2n_ktls_mode ktls_mode,
        struct s2n_key_material *key_material, struct tls12_crypto_info_aes_gcm_128 *crypto_info);
#endif
S2N_RESULT s2n_ktls_retrieve_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd);
S2N_RESULT s2n_ktls_retrieve_io_mode(s2n_ktls_mode ktls_mode, int *tls_tx_rx_mode);

S2N_RESULT s2n_test_configure_connection_for_ktls(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    /* config I/O */
    RESULT_GUARD_POSIX(s2n_connection_set_write_fd(conn, 1));
    RESULT_GUARD_POSIX(s2n_connection_set_read_fd(conn, 1));
    conn->ktls_send_enabled = false;
    conn->ktls_recv_enabled = false;

    /* set kTLS supported cipher */
    conn->secure->cipher_suite = &s2n_rsa_with_aes_128_gcm_sha256;
    conn->actual_protocol_version = S2N_TLS12;
    /* configure connection so that the handshake is complete */
    RESULT_GUARD(s2n_skip_handshake(conn));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_ktls_is_supported_on_platform()) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);

        END_TEST();
    }

    /* prepare test data */
    uint8_t test_data[S2N_MAX_KEY_BLOCK_LEN] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test ktls_supported ciphers */
    {
        struct s2n_cipher cipher = s2n_aes128_gcm;
        EXPECT_TRUE(cipher.ktls_supported);

        cipher = s2n_aes256_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_tls13_aes128_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_tls13_aes256_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_chacha20_poly1305;
        EXPECT_FALSE(cipher.ktls_supported);
    };

    /* Test s2n_ktls_retrieve_file_descriptor */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int write_fd_orig = 1;
        int read_fd_orig = 2;
        int fd_ret = 0;

        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, write_fd_orig));
        EXPECT_OK(s2n_ktls_retrieve_file_descriptor(server_conn, S2N_KTLS_MODE_SEND, &fd_ret));
        EXPECT_EQUAL(write_fd_orig, fd_ret);

        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, read_fd_orig));
        EXPECT_OK(s2n_ktls_retrieve_file_descriptor(server_conn, S2N_KTLS_MODE_RECV, &fd_ret));
        EXPECT_EQUAL(read_fd_orig, fd_ret);
    };

    /* Test s2n_connection_ktls_enable_recv/send */
    {
        /* Success case with a real TLS1.2 negotiated server and client */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key,
                    s2n_cert_chain_and_key_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);

            /* setup config */
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            /* setup IO */
            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* negotiate */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

            uint8_t io_ctx = 0;
            uint8_t io_buf[3] = { 0 };

            /* enable kTLS send */
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));
            EXPECT_TRUE(server_conn->ktls_send_enabled);
            EXPECT_FAILURE_WITH_ERRNO(server_conn->send(&io_ctx, io_buf, 0), S2N_ERR_IO);

            /* enable kTLS recv */
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
            EXPECT_TRUE(server_conn->ktls_recv_enabled);
            EXPECT_FAILURE_WITH_ERRNO(server_conn->recv(&io_ctx, io_buf, 0), S2N_ERR_IO);

            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        }

        /* Success case */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));
            EXPECT_TRUE(server_conn->ktls_send_enabled);

            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
            EXPECT_TRUE(server_conn->ktls_recv_enabled);
        };

        /* Noop if kTLS is already enabled */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            server_conn->ktls_send_enabled = true;
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));

            server_conn->ktls_recv_enabled = true;
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
        };

        /* Fail if handshake is not complete */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));
            server_conn->handshake.message_number = 0;

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_HANDSHAKE_NOT_COMPLETE);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_HANDSHAKE_NOT_COMPLETE);
        };

        /* Fail if unsupported protocols */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);

            server_conn->actual_protocol_version = S2N_TLS11;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);
        };

        /* Fail if unsupported ciphers */
        {
            /* set kTLS unsupported cipher */
            struct s2n_cipher ktls_temp_unsupported_cipher = {
                .ktls_supported = false,
            };
            struct s2n_record_algorithm ktls_temp_unsupported_record_alg = {
                .cipher = &ktls_temp_unsupported_cipher,
            };
            struct s2n_cipher_suite ktls_temp_unsupported_cipher_suite = {
                .record_alg = &ktls_temp_unsupported_record_alg,
            };

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            server_conn->secure->cipher_suite = &ktls_temp_unsupported_cipher_suite;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);
        };

        /* Fail if buffers are not drained */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            uint8_t write_byte = 8;
            uint8_t read_byte = 0;
            /* write to conn->out buffer and assert error */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&server_conn->out, write_byte));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            /* drain conn->out buffer and assert success case */
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&server_conn->out, &read_byte, 1));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));

            /* write to conn->in buffer and assert error */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&server_conn->in, write_byte));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            /* drain conn->in buffer and assert success case */
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&server_conn->in, &read_byte, 1));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
        };

        /* Fail if not using managed IO for send */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            /* expect failure if connection is using custom IO */
            server_conn->managed_send_io = false;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_MANAGED_IO);

            /* expect success if connection is NOT using custom IO */
            server_conn->managed_send_io = true;
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));
        };

        /* Fail if not using managed IO for recv */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            /* recv managed io */
            server_conn->managed_recv_io = false;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_MANAGED_IO);

            /* expect success if connection is NOT using custom IO */
            server_conn->managed_recv_io = true;
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
        };
    }

    /* Test s2n_ktls_init_aes128_gcm_crypto_info */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key,
                s2n_cert_chain_and_key_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);

        /* setup config */
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* setup IO */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* negotiate */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        /* copy test data to key_material */
        struct s2n_key_material key_material = { 0 };
        EXPECT_OK(s2n_key_material_init(&key_material, server_conn));
        POSIX_CHECKED_MEMCPY(key_material.key_block, test_data, s2n_array_len(key_material.key_block));

        POSIX_ENSURE_EQ(key_material.client_key.size, S2N_TLS_AES_128_GCM_KEY_LEN);
        POSIX_ENSURE_EQ(key_material.server_key.size, S2N_TLS_AES_128_GCM_KEY_LEN);

#if defined(S2N_KTLS_SUPPORTED)
        struct tls12_crypto_info_aes_gcm_128 crypto_info = { 0 };

        int ktls_mode = S2N_KTLS_MODE_SEND;
        /* server should send with its own keys */
        EXPECT_OK(s2n_ktls_init_aes128_gcm_crypto_info(server_conn, ktls_mode, &key_material, &crypto_info));
        EXPECT_EQUAL(memcmp(key_material.server_key.data, crypto_info.key, key_material.server_key.size), 0);
        /* client should send with its own keys */
        EXPECT_OK(s2n_ktls_init_aes128_gcm_crypto_info(client_conn, ktls_mode, &key_material, &crypto_info));
        EXPECT_EQUAL(memcmp(key_material.client_key.data, crypto_info.key, key_material.client_key.size), 0);

        ktls_mode = S2N_KTLS_MODE_RECV;
        /* server should recv with its peers keys */
        EXPECT_OK(s2n_ktls_init_aes128_gcm_crypto_info(server_conn, ktls_mode, &key_material, &crypto_info));
        EXPECT_EQUAL(memcmp(key_material.client_key.data, crypto_info.key, key_material.client_key.size), 0);
        /* client should recv with its peers keys */
        EXPECT_OK(s2n_ktls_init_aes128_gcm_crypto_info(client_conn, ktls_mode, &key_material, &crypto_info));
        EXPECT_EQUAL(memcmp(key_material.server_key.data, crypto_info.key, key_material.server_key.size), 0);
#endif

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Test s2n_ktls_retrieve_io_mode */
    {
        int tls_tx_rx_mode = 0;

        EXPECT_OK(s2n_ktls_retrieve_io_mode(S2N_KTLS_MODE_SEND, &tls_tx_rx_mode));
        EXPECT_EQUAL(tls_tx_rx_mode, S2N_TLS_TX);

        EXPECT_OK(s2n_ktls_retrieve_io_mode(S2N_KTLS_MODE_RECV, &tls_tx_rx_mode));
        EXPECT_EQUAL(tls_tx_rx_mode, S2N_TLS_RX);
    }

    END_TEST();
}
