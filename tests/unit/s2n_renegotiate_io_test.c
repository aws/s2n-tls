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
#include "tls/s2n_renegotiate.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"

/* We use bitflags to test every combination
 * of where application data could appear in renegotiation.
 *
 * So app_data_case==6 would mean "110", so we would be testing
 * a renegotiation handshake that received application data
 * before and after the server hello.
 */
enum S2N_TEST_APP_DATA_CASES {
    S2N_TEST_APP_DATA_BEFORE_RENEG = 1,
    S2N_TEST_APP_DATA_BEFORE_SERVER_HELLO = 2,
    S2N_TEST_APP_DATA_AFTER_SERVER_HELLO = 4,
    S2N_TEST_MAX_TEST_CASES = 8,
};
#define S2N_TEST_APP_DATA_LEN 10

static S2N_RESULT s2n_renegotiate_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    ssize_t app_data_read = 0;
    uint8_t recv_buffer[1] = { 0 };
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    while (s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked) != S2N_SUCCESS) {
        RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_IO_BLOCKED);
        RESULT_ENSURE_EQ(blocked, S2N_BLOCKED_ON_READ);
        RESULT_ENSURE_EQ(app_data_read, 0);
        s2n_negotiate(server_conn, &blocked);
    }
    return S2N_RESULT_OK;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    uint8_t app_data[] = "test application data";

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    /* Test basic renegotiation */
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

        /* First handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

        /* Second handshake */
        EXPECT_OK(s2n_renegotiate_test_server_and_client(server_conn, client_conn));
    };

    /* Test that s2n_renegotiate can handle ApplicationData */
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

        ssize_t app_data_read = 0;
        uint8_t recv_buffer[sizeof(app_data)] = { 0 };

        /* First handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

        /* Server sends ApplicationData */
        EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));

        /* Client receives ApplicationData */
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                S2N_ERR_APP_DATA_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_DATA);
        EXPECT_EQUAL(app_data_read, sizeof(app_data));
        EXPECT_BYTEARRAY_EQUAL(recv_buffer, app_data, sizeof(app_data));

        /* Client also made progress on the handshake */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);

        /* Finish renegotiation */
        EXPECT_OK(s2n_renegotiate_test_server_and_client(server_conn, client_conn));
    };

    /* Test that s2n_renegotiate can handle an ApplicationData fragment larger than the receive buffer */
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

        ssize_t app_data_read = 0;
        uint8_t recv_buffer[sizeof(app_data)] = { 0 };

        /* First handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

        /* Server sends ApplicationData */
        EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));

        /* Client receives first part of ApplicationData */
        const size_t first_read_len = 2;
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, first_read_len, &app_data_read, &blocked),
                S2N_ERR_APP_DATA_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_DATA);
        EXPECT_EQUAL(app_data_read, first_read_len);
        EXPECT_BYTEARRAY_EQUAL(recv_buffer, app_data, first_read_len);

        /* Client also made progress on the handshake */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);

        /* Client receives second part of ApplicationData */
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer + first_read_len,
                                          sizeof(app_data) - first_read_len, &app_data_read, &blocked),
                S2N_ERR_APP_DATA_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_DATA);
        EXPECT_EQUAL(app_data_read, sizeof(app_data) - first_read_len);
        EXPECT_BYTEARRAY_EQUAL(recv_buffer, app_data, sizeof(app_data));

        /* Client waits for more data */
        for (size_t i = 0; i < 10; i++) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer),
                                              &app_data_read, &blocked),
                    S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            EXPECT_EQUAL(app_data_read, 0);
        }

        /* Finish renegotiation */
        EXPECT_OK(s2n_renegotiate_test_server_and_client(server_conn, client_conn));
    };

    /* Test that s2n_renegotiate can handle multiple ApplicationData records */
    {
        const size_t app_data_record_count = 10;

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        ssize_t app_data_read = 0;
        uint8_t recv_buffer[sizeof(app_data)] = { 0 };

        /* First handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

        /* Server sends ApplicationData */
        for (size_t i = 0; i < app_data_record_count; i++) {
            EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
        }

        /* Client receives ApplicationData */
        for (size_t i = 0; i < app_data_record_count; i++) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer),
                                              &app_data_read, &blocked),
                    S2N_ERR_APP_DATA_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_DATA);
            EXPECT_EQUAL(app_data_read, sizeof(app_data));
            EXPECT_BYTEARRAY_EQUAL(recv_buffer, app_data, sizeof(app_data));
            memset(recv_buffer, 0, sizeof(recv_buffer));
        }

        /* Client also made progress on the handshake */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);

        /* Finish renegotiation */
        EXPECT_OK(s2n_renegotiate_test_server_and_client(server_conn, client_conn));
    };

    /* Test that s2n_renegotiate rejects ApplicationData after receiving the ServerHello */
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

        ssize_t app_data_read = 0;
        uint8_t recv_buffer[sizeof(app_data)] = { 0 };

        /* First handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

        /* Client writes ClientHello */
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Server writes ServerHello */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_NOT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
        EXPECT_TRUE(IS_NEGOTIATED(server_conn));
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Server sends ApplicationData */
        EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));

        /* Client rejects ApplicationData */
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                S2N_ERR_BAD_MESSAGE);
        EXPECT_NOT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
        EXPECT_TRUE(IS_NEGOTIATED(server_conn));
    };

    /* Test that s2n_renegotiate rejects incorrect handshake messages */
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

        ssize_t app_data_read = 0;
        uint8_t recv_buffer[sizeof(app_data)] = { 0 };

        /* First handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

        /* Client writes ClientHello */
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Server reads ClientHello */
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, SERVER_HELLO));

        /* Server writes wrong message.
         * We use "SERVER_HELLO_DONE" because it's an empty message and requires no setup.
         */
        server_conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        server_conn->handshake.message_number = 3;
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO_DONE);
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_IO_BLOCKED);

        /* Client rejects unexpected message */
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
    };

    /* Test that s2n_renegotiate handles handshake IO blocked on send */
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

        uint8_t recv_buffer[1] = { 0 };

        /* First handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
        EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));

        /* Block send IO with empty buffer */
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&output, client_conn));

        /* Verify send is blocked on write */
        ssize_t app_data_read = 0;
        for (size_t i = 0; i < 10; i++) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                    S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            EXPECT_EQUAL(app_data_read, 0);
        }

        /* Unblock send IO by allocating buffer */
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

        /* Verify send blocks on read */
        EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        EXPECT_EQUAL(app_data_read, 0);
    };

    /* Test timing of application data during the renegotiation handshake.
     *
     * We want to ensure that s2n_renegotiate can handle ApplicationData at any time.
     */
    {
        uint8_t messages[][S2N_TEST_APP_DATA_LEN] = {
            "one", "two", "three"
        };
        EXPECT_EQUAL(1 << s2n_array_len(messages), S2N_TEST_MAX_TEST_CASES);

        /* Sanity checks
         * We want to ensure all interesting cases are hit at least once.
         */
        bool reneg_ch_had_app_data = false;
        bool reneg_ch_had_no_app_data = false;
        bool reneg_extra_app_data = false;
        bool reneg_sh_had_app_data = false;
        bool reneg_sh_had_no_app_data = false;

        for (size_t app_data_case = 0; app_data_case < S2N_TEST_MAX_TEST_CASES; app_data_case++) {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            ssize_t app_data_read = 0;
            uint8_t recv_buffer[S2N_TEST_APP_DATA_LEN * 2] = { 0 };
            size_t send_i = 0, recv_i = 0;

            /* First handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Before Renegotiation */
            {
                if (app_data_case & S2N_TEST_APP_DATA_BEFORE_RENEG) {
                    EXPECT_EQUAL(s2n_send(server_conn, messages[send_i], S2N_TEST_APP_DATA_LEN, &blocked), S2N_TEST_APP_DATA_LEN);
                    send_i++;
                }

                EXPECT_SUCCESS(s2n_renegotiate_wipe(server_conn));
                EXPECT_SUCCESS(s2n_renegotiate_wipe(client_conn));
            };

            /* Client: ClientHello sent */
            {
                int r = s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked);
                EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
                /* Expect to have received any outstanding application data */
                if (send_i > 0 && recv_i < send_i) {
                    EXPECT_FAILURE_WITH_ERRNO(r, S2N_ERR_APP_DATA_BLOCKED);
                    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_DATA);
                    EXPECT_EQUAL(app_data_read, S2N_TEST_APP_DATA_LEN);
                    EXPECT_BYTEARRAY_EQUAL(recv_buffer, messages[recv_i], S2N_TEST_APP_DATA_LEN);
                    recv_i++;
                    reneg_ch_had_app_data = true;
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(r, S2N_ERR_IO_BLOCKED);
                    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
                    EXPECT_EQUAL(app_data_read, 0);
                    reneg_ch_had_no_app_data = true;
                }
            };

            /* Server: ClientHello recv, ServerHello sent */
            {
                if (app_data_case & S2N_TEST_APP_DATA_BEFORE_SERVER_HELLO) {
                    EXPECT_EQUAL(s2n_send(server_conn, messages[send_i], S2N_TEST_APP_DATA_LEN, &blocked), S2N_TEST_APP_DATA_LEN);
                    send_i++;
                }

                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
                EXPECT_NOT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
                EXPECT_TRUE(IS_NEGOTIATED(server_conn));

                /* All application data sent after the ServerHello is invalid.
                 * We specifically don't increment sent_i, because we won't use this data.
                 */
                if (app_data_case & S2N_TEST_APP_DATA_AFTER_SERVER_HELLO) {
                    EXPECT_EQUAL(s2n_send(server_conn, messages[send_i], S2N_TEST_APP_DATA_LEN, &blocked), S2N_TEST_APP_DATA_LEN);
                }
            };

            /* Client: ApplicationData recv */
            while (send_i > 0 && recv_i < send_i) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked),
                        S2N_ERR_APP_DATA_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_DATA);
                EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
                EXPECT_EQUAL(app_data_read, S2N_TEST_APP_DATA_LEN);
                EXPECT_BYTEARRAY_EQUAL(recv_buffer, messages[recv_i], S2N_TEST_APP_DATA_LEN);
                recv_i++;
                reneg_extra_app_data = true;
            }

            /* Client: ServerHello recv */
            {
                int r = s2n_renegotiate(client_conn, recv_buffer, sizeof(recv_buffer), &app_data_read, &blocked);

                /* No application data is allowed after the ServerHello */
                if (app_data_case & S2N_TEST_APP_DATA_AFTER_SERVER_HELLO) {
                    EXPECT_FAILURE_WITH_ERRNO(r, S2N_ERR_BAD_MESSAGE);
                    reneg_sh_had_app_data = true;
                    continue;
                }

                EXPECT_FAILURE_WITH_ERRNO(r, S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
                EXPECT_NOT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
                EXPECT_TRUE(IS_NEGOTIATED(client_conn));
                reneg_sh_had_no_app_data = true;
            };

            /* Handshake completes */
            EXPECT_OK(s2n_renegotiate_test_server_and_client(server_conn, client_conn));
        }

        EXPECT_TRUE(reneg_ch_had_app_data);
        EXPECT_TRUE(reneg_ch_had_no_app_data);
        EXPECT_TRUE(reneg_extra_app_data);
        EXPECT_TRUE(reneg_sh_had_app_data);
        EXPECT_TRUE(reneg_sh_had_no_app_data);
    };

    END_TEST();
}
