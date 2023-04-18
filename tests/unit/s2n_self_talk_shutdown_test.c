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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    /* Self-Talk: shutdown during handshake */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));
        EXPECT_FALSE(s2n_handshake_is_complete(client_conn));
        EXPECT_FALSE(s2n_handshake_is_complete(server_conn));

        /* Choose which connection will request the shutdown */
        struct s2n_connection *request = server_conn;
        struct s2n_connection *response = client_conn;
        if (modes[mode_i] == S2N_CLIENT) {
            request = client_conn;
            response = server_conn;
        }

        /* Both shutdown attempts should succeed */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown(request, &blocked));
        EXPECT_SUCCESS(s2n_shutdown(response, &blocked));

        /* Both connections successfully closed */
        EXPECT_TRUE(s2n_connection_check_io_status(server_conn, S2N_IO_CLOSED));
        EXPECT_TRUE(s2n_connection_check_io_status(client_conn, S2N_IO_CLOSED));

        /* Closed connections behave properly */
        for (size_t i = 0; i < 5; i++) {
            /* Future attempts to shutdown succeed (they are no-ops) */
            EXPECT_SUCCESS(s2n_shutdown(server_conn, &blocked));
            EXPECT_SUCCESS(s2n_shutdown(client_conn, &blocked));
        }
    };

    /* Self-Talk: shutdown during application data */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Both the client and server should send application data, but not read any.
         * This leaves unread application data for both to handle.
         */
        uint8_t data[] = "hello world";
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_send(server_conn, data, sizeof(data), &blocked), sizeof(data));
        EXPECT_EQUAL(s2n_send(client_conn, data, sizeof(data), &blocked), sizeof(data));

        /* Choose which connection will request the shutdown, and which will respond */
        struct s2n_connection *request = server_conn;
        struct s2n_connection *response = client_conn;
        if (modes[mode_i] == S2N_CLIENT) {
            request = client_conn;
            response = server_conn;
        }

        /* The requester's first shutdown attempt will send a close_notify
         * but then block on receiving the response close_notify.
         */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(request, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* The responder's first shutdown attempt will receive the request close_notify,
         * send the response close_notify, and then consider the shutdown successful.
         */
        EXPECT_SUCCESS(s2n_shutdown(response, &blocked));

        /* The requester's second shutdown attempt will receive the response close_notify
         * and then consider the shutdown successful.
         */
        EXPECT_SUCCESS(s2n_shutdown(request, &blocked));

        /* Both connections successfully closed */
        EXPECT_TRUE(s2n_connection_check_io_status(server_conn, S2N_IO_CLOSED));
        EXPECT_TRUE(s2n_connection_check_io_status(client_conn, S2N_IO_CLOSED));

        /* Closed connections behave properly */
        for (size_t i = 0; i < 5; i++) {
            /* Future attempts to shutdown succeed (they are no-ops) */
            EXPECT_SUCCESS(s2n_shutdown(server_conn, &blocked));
            EXPECT_SUCCESS(s2n_shutdown(client_conn, &blocked));

            /* Future attempts to write fail */
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(server_conn, data, sizeof(data), &blocked), S2N_ERR_CLOSED);
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, data, sizeof(data), &blocked), S2N_ERR_CLOSED);

            /* Future attempts to read indicate end of stream */
            EXPECT_EQUAL(s2n_recv(server_conn, data, sizeof(data), &blocked), 0);
            EXPECT_EQUAL(s2n_recv(client_conn, data, sizeof(data), &blocked), 0);
        }
    };

    END_TEST();
}
