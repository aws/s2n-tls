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

#include <sys/socket.h>

#include "crypto/s2n_cipher.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_handshake_type.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn);
S2N_RESULT s2n_ktls_validate_socket_mode(struct s2n_connection *conn, s2n_ktls_mode ktls_mode);
S2N_RESULT s2n_ktls_retrieve_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* ktls_supported ciphers */
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
    }

    /* s2n_ktls_validate TLS 1.2 */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        uint8_t key_size = server_conn->secure->cipher_suite->record_alg->cipher->key_material_size;
        EXPECT_EQUAL(key_size, S2N_TLS_AES_128_GCM_KEY_LEN);

        EXPECT_OK(s2n_ktls_validate(server_conn));
    }

    /* s2n_ktls_validate TLS 1.3 */
    {
        if (s2n_is_tls13_fully_supported()) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            uint8_t key_size = server_conn->secure->cipher_suite->record_alg->cipher->key_material_size;
            EXPECT_EQUAL(key_size, S2N_TLS_AES_128_GCM_KEY_LEN);

            EXPECT_ERROR(s2n_ktls_validate(server_conn));
        }
    }

    /* s2n_ktls_validate_socket_mode */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 1;
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, fd));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, fd));
        server_conn->managed_recv_io = false;

        /* base case */
        server_conn->managed_send_io = false;
        server_conn->ktls_send_enabled = false;
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV));
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND));

        /* managed io */
        server_conn->managed_send_io = true;
        server_conn->ktls_send_enabled = false;
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV));
        EXPECT_ERROR(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND));

        /* ktls enabled */
        server_conn->managed_send_io = false;
        server_conn->ktls_send_enabled = true;
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV));
        EXPECT_ERROR(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND));

        /* reset value so we cleanup properly */
        server_conn->managed_send_io = true;
        server_conn->managed_recv_io = true;
    }

    /* s2n_ktls_retrieve_file_descriptor */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 1;
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, fd));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, fd));
        server_conn->managed_recv_io = false;
        server_conn->managed_send_io = false;

        int fd_ret = 0;
        EXPECT_OK(s2n_ktls_retrieve_file_descriptor(server_conn, S2N_KTLS_MODE_SEND, &fd_ret));
        EXPECT_EQUAL(fd, fd_ret);

        /* reset value so we cleanup properly */
        server_conn->managed_send_io = true;
        server_conn->managed_recv_io = true;
    }

    END_TEST();
}
