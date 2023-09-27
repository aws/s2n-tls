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
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_ktls_parameters.h"
#include "utils/s2n_random.h"
#include "utils/s2n_socket.h"

#define S2N_TEST_SEND_FD 66
#define S2N_TEST_RECV_FD 55

static int s2n_test_setsockopt_noop(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    return S2N_SUCCESS;
}

static int s2n_test_setsockopt_tcp_error(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (level == S2N_SOL_TCP) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int s2n_test_setsockopt_tls_error(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (level == S2N_SOL_TLS) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int s2n_test_setsockopt_tx(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    POSIX_ENSURE_EQ(fd, S2N_TEST_SEND_FD);

    if (level == S2N_SOL_TLS) {
        POSIX_ENSURE_EQ(optname, S2N_TLS_TX);
#if defined(S2N_KTLS_SUPPORTED)
        POSIX_ENSURE_EQ(optlen, sizeof(struct tls12_crypto_info_aes_gcm_128));
#endif
    } else if (level == S2N_SOL_TCP) {
        POSIX_ENSURE_EQ(optname, S2N_TCP_ULP);
        POSIX_ENSURE_EQ(optlen, S2N_TLS_ULP_NAME_SIZE);
    } else {
        POSIX_BAIL(S2N_ERR_SAFETY);
    }
    return S2N_SUCCESS;
}

static int s2n_test_setsockopt_rx(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    POSIX_ENSURE_EQ(fd, S2N_TEST_RECV_FD);

    if (level == S2N_SOL_TLS) {
        POSIX_ENSURE_EQ(optname, S2N_TLS_RX);
#if defined(S2N_KTLS_SUPPORTED)
        POSIX_ENSURE_EQ(optlen, sizeof(struct tls12_crypto_info_aes_gcm_128));
#endif
    } else if (level == S2N_SOL_TCP) {
        POSIX_ENSURE_EQ(optname, S2N_TCP_ULP);
        POSIX_ENSURE_EQ(optlen, S2N_TLS_ULP_NAME_SIZE);
    } else {
        POSIX_BAIL(S2N_ERR_SAFETY);
    }
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_test_configure_connection_for_ktls(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    RESULT_GUARD(s2n_ktls_set_setsockopt_cb(s2n_test_setsockopt_noop));

    /* config I/O */
    RESULT_GUARD_POSIX(s2n_connection_set_write_fd(conn, S2N_TEST_SEND_FD));
    RESULT_GUARD_POSIX(s2n_connection_set_read_fd(conn, S2N_TEST_RECV_FD));
    conn->ktls_send_enabled = false;
    conn->ktls_recv_enabled = false;

    /* set kTLS supported cipher */
    conn->secure->cipher_suite = &s2n_rsa_with_aes_128_gcm_sha256;
    conn->actual_protocol_version = S2N_TLS12;
    /* configure connection so that the handshake is complete */
    RESULT_GUARD(s2n_skip_handshake(conn));

    return S2N_RESULT_OK;
}

static int s2n_test_reneg_cb(struct s2n_connection *conn, void *context,
        s2n_renegotiate_response *response)
{
    return S2N_SUCCESS;
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

    /* Test set_ktls_info for ciphers */
    {
        struct s2n_crypto_parameters crypto_params = { 0 };

        struct s2n_blob test_iv = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&test_iv, crypto_params.client_implicit_iv,
                sizeof(crypto_params.client_implicit_iv)));
        EXPECT_OK(s2n_get_public_random_data(&test_iv));

        struct s2n_blob test_seq = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&test_seq, crypto_params.client_sequence_number,
                sizeof(crypto_params.client_sequence_number)));
        EXPECT_OK(s2n_get_public_random_data(&test_seq));

        /* s2n_aes128_gcm */
        {
            DEFER_CLEANUP(struct s2n_blob test_key = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&test_key, s2n_aes128_gcm.key_material_size));
            EXPECT_OK(s2n_get_public_random_data(&test_key));

            struct s2n_ktls_crypto_info_inputs inputs = {
                .key = test_key,
                .iv = test_iv,
                .seq = test_seq,
            };

            struct s2n_ktls_crypto_info crypto_info = { 0 };
            EXPECT_OK(s2n_aes128_gcm.set_ktls_info(&inputs, &crypto_info));
            EXPECT_EQUAL(crypto_info.value.size, sizeof(crypto_info.ciphers.aes_gcm_128));
            EXPECT_EQUAL(crypto_info.value.data, (uint8_t *) &crypto_info.ciphers.aes_gcm_128);
            s2n_ktls_crypto_info_tls12_aes_gcm_128 *value =
                    (s2n_ktls_crypto_info_tls12_aes_gcm_128 *) crypto_info.value.data;

            EXPECT_EQUAL(test_key.size, sizeof(value->key));
            EXPECT_BYTEARRAY_EQUAL(test_key.data, value->key, sizeof(value->key));

            EXPECT_TRUE(test_iv.size >= sizeof(value->iv));
            EXPECT_BYTEARRAY_EQUAL(test_iv.data, value->iv, sizeof(value->iv));

            EXPECT_TRUE(test_iv.size >= sizeof(value->salt));
            EXPECT_BYTEARRAY_EQUAL(test_iv.data, value->salt, sizeof(value->salt));

            EXPECT_TRUE(test_seq.size >= sizeof(value->rec_seq));
            EXPECT_BYTEARRAY_EQUAL(test_seq.data, value->rec_seq, sizeof(value->rec_seq));
        };

        /* s2n_aes256_gcm */
        {
            DEFER_CLEANUP(struct s2n_blob test_key = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&test_key, s2n_aes256_gcm.key_material_size));
            EXPECT_OK(s2n_get_public_random_data(&test_key));

            struct s2n_ktls_crypto_info_inputs inputs = {
                .key = test_key,
                .iv = test_iv,
                .seq = test_seq,
            };

            struct s2n_ktls_crypto_info crypto_info = { 0 };
            EXPECT_OK(s2n_aes256_gcm.set_ktls_info(&inputs, &crypto_info));
            EXPECT_EQUAL(crypto_info.value.size, sizeof(crypto_info.ciphers.aes_gcm_256));
            EXPECT_EQUAL(crypto_info.value.data, (uint8_t *) &crypto_info.ciphers.aes_gcm_256);
            s2n_ktls_crypto_info_tls12_aes_gcm_256 *value =
                    (s2n_ktls_crypto_info_tls12_aes_gcm_256 *) crypto_info.value.data;

            EXPECT_EQUAL(test_key.size, sizeof(value->key));
            EXPECT_BYTEARRAY_EQUAL(test_key.data, value->key, sizeof(value->key));

            EXPECT_TRUE(test_iv.size >= sizeof(value->iv));
            EXPECT_BYTEARRAY_EQUAL(test_iv.data, value->iv, sizeof(value->iv));

            EXPECT_TRUE(test_iv.size >= sizeof(value->salt));
            EXPECT_BYTEARRAY_EQUAL(test_iv.data, value->salt, sizeof(value->salt));

            EXPECT_TRUE(test_seq.size >= sizeof(value->rec_seq));
            EXPECT_BYTEARRAY_EQUAL(test_seq.data, value->rec_seq, sizeof(value->rec_seq));
        };
    };

    /* Test s2n_connection_ktls_enable_recv/send */
    {
        /* enable TX/RX */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));

            EXPECT_OK(s2n_ktls_set_setsockopt_cb(s2n_test_setsockopt_tx));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));
            EXPECT_TRUE(server_conn->ktls_send_enabled);

            EXPECT_OK(s2n_ktls_set_setsockopt_cb(s2n_test_setsockopt_rx));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
            EXPECT_TRUE(server_conn->ktls_recv_enabled);
        };

        /* handle setsockopt error for S2N_SOL_TCP */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));
            EXPECT_OK(s2n_ktls_set_setsockopt_cb(s2n_test_setsockopt_tcp_error));

            /* The error does not prevent us from enabling ktls */
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
        };

        /* handle setsockopt error for S2N_SOL_TLS */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server_conn));
            EXPECT_OK(s2n_ktls_set_setsockopt_cb(s2n_test_setsockopt_tls_error));

            /* The error prevents us from enabling ktls */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn),
                    S2N_ERR_KTLS_ENABLE);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn),
                    S2N_ERR_KTLS_ENABLE);
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
                .set_ktls_info = NULL,
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

        /* Fail if renegotiation potentially supported */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(client));
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_OK(s2n_test_configure_connection_for_ktls(server));
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, s2n_test_reneg_cb, NULL));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(client), S2N_ERR_KTLS_RENEG);
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server));
        };
    };

    /* selftalk: Success case with a real TLS1.2 negotiated server and client */
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
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170210"));
        EXPECT_OK(s2n_ktls_set_setsockopt_cb(s2n_test_setsockopt_noop));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* setup IO and negotiate */
        DEFER_CLEANUP(struct s2n_test_io_pair test_io_pair = { 0 },
                s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&test_io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &test_io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        /* enable kTLS send */
        EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server_conn));
        EXPECT_TRUE(server_conn->ktls_send_enabled);
        EXPECT_NOT_EQUAL(server_conn->send, s2n_socket_write);

        /* enable kTLS recv */
        EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server_conn));
        EXPECT_TRUE(server_conn->ktls_recv_enabled);
        EXPECT_NOT_EQUAL(server_conn->recv, s2n_socket_read);
    };

    END_TEST();
}
