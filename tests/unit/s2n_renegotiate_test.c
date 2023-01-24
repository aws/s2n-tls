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

#include "tls/s2n_renegotiate.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"

struct s2n_reneg_test_case {
    uint8_t protocol_version;
    struct s2n_cipher_suite *cipher_suite;
    uint8_t max_frag_code;
};

const struct s2n_reneg_test_case dhe_test_cases[] = {
    {
            .protocol_version = S2N_SSLv3,
            .cipher_suite = &s2n_dhe_rsa_with_3des_ede_cbc_sha,
            .max_frag_code = 0,
    },
    {
            .protocol_version = S2N_TLS10,
            .cipher_suite = &s2n_dhe_rsa_with_aes_128_cbc_sha,
            .max_frag_code = S2N_TLS_MAX_FRAG_LEN_512,
    },
    {
            .protocol_version = S2N_TLS11,
            .cipher_suite = &s2n_dhe_rsa_with_aes_256_cbc_sha,
            .max_frag_code = S2N_TLS_MAX_FRAG_LEN_1024,
    },
    {
            .protocol_version = S2N_TLS12,
            .cipher_suite = &s2n_dhe_rsa_with_aes_128_cbc_sha256,
            .max_frag_code = 0,
    },
    {
            .protocol_version = S2N_TLS12,
            .cipher_suite = &s2n_dhe_rsa_with_aes_256_gcm_sha384,
            .max_frag_code = S2N_TLS_MAX_FRAG_LEN_2048,
    },
    {
            .protocol_version = S2N_TLS12,
            .cipher_suite = &s2n_dhe_rsa_with_chacha20_poly1305_sha256,
            .max_frag_code = S2N_TLS_MAX_FRAG_LEN_4096,
    },
};

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    char dh_params[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dh_params, sizeof(dh_params)));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    uint8_t app_data[] = "smaller hello world";
    uint8_t large_app_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = "hello world and a lot of zeroes";
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    /* Test s2n_renegotiate_wipe */
    {
        /* Default IO unaffected by wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            /* "io_pair" just uses file descriptors and the default io callbacks */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));
            EXPECT_EQUAL(client_conn->send, s2n_socket_write);
            EXPECT_TRUE(client_conn->managed_send_io);
            EXPECT_EQUAL(client_conn->recv, s2n_socket_read);
            EXPECT_TRUE(client_conn->managed_recv_io);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));

            uint8_t recv_buffer[sizeof(app_data)] = { 0 };
            EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_recv(client_conn, recv_buffer, sizeof(recv_buffer), &blocked), sizeof(app_data));
            EXPECT_BYTEARRAY_EQUAL(recv_buffer, app_data, sizeof(app_data));
        };

        /* Custom IO callbacks unaffected by wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            /* "io_stuffers" use custom IO callbacks written for tests */
            DEFER_CLEANUP(struct s2n_stuffer in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&in, &out, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&out, &in, server_conn));
            EXPECT_NOT_EQUAL(client_conn->send, s2n_socket_write);
            EXPECT_FALSE(client_conn->managed_send_io);
            EXPECT_NOT_EQUAL(client_conn->recv, s2n_socket_read);
            EXPECT_FALSE(client_conn->managed_recv_io);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));

            uint8_t recv_buffer[sizeof(app_data)] = { 0 };
            EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_recv(client_conn, recv_buffer, sizeof(recv_buffer), &blocked), sizeof(app_data));
            EXPECT_BYTEARRAY_EQUAL(recv_buffer, app_data, sizeof(app_data));
        };

        /* Fragment size unaffected by wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&in, &out, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&out, &in, server_conn));

            EXPECT_SUCCESS(s2n_connection_prefer_low_latency(client_conn));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_EQUAL(s2n_send(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            size_t original_out_size = s2n_stuffer_data_available(&out);
            EXPECT_SUCCESS(s2n_stuffer_wipe(&out));

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));

            EXPECT_EQUAL(s2n_send(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            size_t wiped_out_size = s2n_stuffer_data_available(&out);
            EXPECT_EQUAL(original_out_size, wiped_out_size);
        };

        /* Forced very small fragment size unaffected by wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&in, &out, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&out, &in, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            const size_t small_frag_len = S2N_MIN_SEND_BUFFER_FRAGMENT_SIZE;
            client_conn->max_outgoing_fragment_length = small_frag_len;

            EXPECT_EQUAL(s2n_send(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            size_t original_out_size = s2n_stuffer_data_available(&out);
            EXPECT_SUCCESS(s2n_stuffer_wipe(&out));

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
            EXPECT_EQUAL(client_conn->max_outgoing_fragment_length, small_frag_len);

            EXPECT_EQUAL(s2n_send(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            size_t wiped_out_size = s2n_stuffer_data_available(&out);
            EXPECT_EQUAL(original_out_size, wiped_out_size);
        };

        /* Handshake succeeds after wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
            EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        };

        /* Handshake with added client auth succeeds after wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_NONE));
            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_NONE));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_FALSE(IS_CLIENT_AUTH_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_CLIENT_AUTH_HANDSHAKE(server_conn));

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
            EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_TRUE(IS_CLIENT_AUTH_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_CLIENT_AUTH_NO_CERT(client_conn));
            EXPECT_TRUE(IS_CLIENT_AUTH_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_CLIENT_AUTH_NO_CERT(server_conn));
        };

        /* Handshake with different fragment length succeeds after wipe */
        {
            DEFER_CLEANUP(struct s2n_config *small_frag_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(small_frag_config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(small_frag_config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(small_frag_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(small_frag_config, "default"));
            EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(small_frag_config));
            EXPECT_SUCCESS(s2n_config_send_max_fragment_length(small_frag_config, S2N_TLS_MAX_FRAG_LEN_512));

            DEFER_CLEANUP(struct s2n_config *larger_frag_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(larger_frag_config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(larger_frag_config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(larger_frag_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(larger_frag_config, "default"));
            EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(larger_frag_config));
            EXPECT_SUCCESS(s2n_config_send_max_fragment_length(larger_frag_config, S2N_TLS_MAX_FRAG_LEN_4096));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, larger_frag_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, larger_frag_config));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
            EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, small_frag_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, small_frag_config));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
            EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, larger_frag_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, larger_frag_config));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        };

        /* renegotiation_info is non-empty after wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Verify that the renegotiation_info was empty / missing */
            ssize_t renegotiation_info_len = s2n_client_hello_get_extension_length(&server_conn->client_hello,
                    S2N_EXTENSION_RENEGOTIATION_INFO);
            EXPECT_EQUAL(renegotiation_info_len, 0);

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
            EXPECT_TRUE(client_conn->handshake.finished_len > 0);
            EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Verify that the renegotiation_info was not empty / missing */
            renegotiation_info_len = s2n_client_hello_get_extension_length(&server_conn->client_hello,
                    S2N_EXTENSION_RENEGOTIATION_INFO);
            EXPECT_TRUE(renegotiation_info_len > sizeof(uint8_t));
        };

        /* Wipe of insecure connection not allowed */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            client_conn->actual_protocol_version = S2N_TLS12;

            EXPECT_FALSE(client_conn->secure_renegotiation);
            EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate_wipe(client_conn), S2N_ERR_NO_RENEGOTIATION);
            client_conn->secure_renegotiation = true;
            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        };

        /* Wipe of TLS1.3 connection not allowed */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            client_conn->secure_renegotiation = true;

            EXPECT_TRUE(client_conn->actual_protocol_version > S2N_TLS12);
            EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate_wipe(client_conn), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
            client_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        };

        /* Wipe mid-write not allowed */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&in, &out, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&out, &in, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Initiate a partial send */
            uint16_t partial_send_len = client_conn->max_outgoing_fragment_length / 2;
            DEFER_CLEANUP(struct s2n_stuffer small_out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&small_out, partial_send_len));
            EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&small_out, client_conn));
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, large_app_data, sizeof(large_app_data), &blocked),
                    S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

            EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate_wipe(client_conn), S2N_ERR_INVALID_STATE);

            /* Finish the send */
            EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&out, client_conn));
            EXPECT_EQUAL(s2n_send(client_conn, large_app_data, sizeof(large_app_data), &blocked), sizeof(large_app_data));

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        };

        /* Wipe mid-read not allowed */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_stuffer in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&in, &out, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&out, &in, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Initiate a partial recv */
            uint16_t partial_recv_len = sizeof(app_data) / 2;
            uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_recv(client_conn, recv_buffer, partial_recv_len, &blocked), partial_recv_len);
            EXPECT_BYTEARRAY_EQUAL(app_data, recv_buffer, partial_recv_len);
            EXPECT_TRUE(s2n_peek(client_conn) > 0);

            EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate_wipe(client_conn), S2N_ERR_INVALID_STATE);

            /* Finish the recv */
            size_t remaining_recv_len = sizeof(app_data) - partial_recv_len;
            EXPECT_EQUAL(s2n_recv(client_conn, recv_buffer, remaining_recv_len, &blocked), remaining_recv_len);
            EXPECT_BYTEARRAY_EQUAL(app_data + partial_recv_len, recv_buffer, remaining_recv_len);
            EXPECT_EQUAL(s2n_peek(client_conn), 0);

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        };
    };

    /* Test the basic renegotiation mechanism with a variety of connection parameters.
     * A client should always be able to receive and negotiate after wiping a connection for renegotiation.
     */
    {
        /* Setup a security policy that only contains one cipher */
        struct s2n_cipher_preferences one_cipher_preference = { .count = 1, .suites = NULL };
        struct s2n_security_policy one_cipher_policy = security_policy_test_all;
        one_cipher_policy.cipher_preferences = &one_cipher_preference;

        /* This config can only be used for servers, because currently only servers can have multiple certs */
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dh_params));
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(server_config));
        server_config->security_policy = &one_cipher_policy;

        /* Setting the max fragment length will require modifying the client config */
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));

        /* The oldest version s2n-tls supports is SSLv3.
         * However, SSLv3 requires MD5 for its PRF.
         */
        uint8_t oldest_tested_version = S2N_SSLv3;
        if (!s2n_hash_is_available(S2N_HASH_MD5)) {
            oldest_tested_version = S2N_TLS10;
        }

        struct s2n_reneg_test_case test_cases[2000] = { 0 };
        size_t test_cases_count = 0;

        /* FFDHE is very, VERY slow.
         * To avoid this test taking multiple minutes,
         * we choose a limited number of dhe test cases.
         */
        for (size_t i = 0; i < s2n_array_len(dhe_test_cases); i++) {
            if (!dhe_test_cases[i].cipher_suite->available) {
                continue;
            }
            if (dhe_test_cases[i].protocol_version < oldest_tested_version) {
                continue;
            }
            test_cases[test_cases_count] = dhe_test_cases[i];
            test_cases_count++;
            EXPECT_TRUE(test_cases_count < s2n_array_len(test_cases));
        }
        EXPECT_TRUE(test_cases_count > 0);

        const struct s2n_cipher_preferences *ciphers = security_policy_test_all.cipher_preferences;
        for (uint8_t version = oldest_tested_version; version < S2N_TLS13; version++) {
            for (size_t cipher_i = 0; cipher_i < ciphers->count; cipher_i++) {
                struct s2n_cipher_suite *cipher = ciphers->suites[cipher_i];

                if (!cipher->available) {
                    continue;
                }

                if (version < cipher->minimum_required_tls_version) {
                    continue;
                }

                if (cipher->key_exchange_alg == &s2n_dhe) {
                    /* See dhe_test_cases */
                    continue;
                }

                for (size_t max_frag_i = 0; max_frag_i < s2n_array_len(mfl_code_to_length); max_frag_i++) {
                    test_cases[test_cases_count] = (struct s2n_reneg_test_case){
                        .protocol_version = version,
                        .cipher_suite = ciphers->suites[cipher_i],
                        .max_frag_code = max_frag_i,
                    };
                    test_cases_count++;
                    EXPECT_TRUE(test_cases_count < s2n_array_len(test_cases));
                }
            }
        }

        for (size_t i = 0; i < test_cases_count; i++) {
            uint8_t recv_buffer[sizeof(app_data)] = { 0 };

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            /* Setup test case */
            server_conn->server_protocol_version = test_cases[i].protocol_version;
            EXPECT_SUCCESS(s2n_config_send_max_fragment_length(client_config, test_cases[i].max_frag_code));
            one_cipher_preference.suites = &test_cases[i].cipher_suite;

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Verify test case setup */
            EXPECT_EQUAL(client_conn->actual_protocol_version, test_cases[i].protocol_version);
            EXPECT_EQUAL(client_conn->max_outgoing_fragment_length, mfl_code_to_length[test_cases[i].max_frag_code]);
            if (test_cases[i].protocol_version > S2N_SSLv3) {
                EXPECT_EQUAL(client_conn->secure->cipher_suite, test_cases[i].cipher_suite);
            } else {
                EXPECT_EQUAL(client_conn->secure->cipher_suite, test_cases[i].cipher_suite->sslv3_cipher_suite);
            }

            EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));

            /* Test that the client can still receive application data */
            EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_recv(client_conn, recv_buffer, sizeof(recv_buffer), &blocked), sizeof(app_data));
            EXPECT_BYTEARRAY_EQUAL(recv_buffer, app_data, sizeof(app_data));

            /* Test that a second handshake can occur. */
            EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        }
    };

    END_TEST();
}
