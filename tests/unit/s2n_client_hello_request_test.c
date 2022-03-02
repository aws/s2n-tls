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

#include "tls/s2n_tls.h"

static const uint8_t hello_request_msg[] = {
    /* message header */
    TLS_HELLO_REQUEST,    /* msg_type = hello_request */
    0, 0, 0,              /* length = 0 */
    /* empty message body */
};

static S2N_RESULT s2n_test_send_and_recv(struct s2n_connection *send_conn, struct s2n_connection *recv_conn)
{
    RESULT_ENSURE_REF(send_conn);
    RESULT_ENSURE_REF(recv_conn);

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    const uint8_t send_data[] = "hello world";
    ssize_t send_size = s2n_send(send_conn, send_data, sizeof(send_data), &blocked);
    RESULT_ENSURE_EQ(send_size, sizeof(send_data));

    uint8_t recv_data[sizeof(send_data)] = { 0 };
    ssize_t recv_size = s2n_recv(recv_conn, recv_data, send_size, &blocked);
    RESULT_ENSURE_EQ(recv_size, send_size);
    EXPECT_BYTEARRAY_EQUAL(recv_data, send_data, send_size);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_send_client_hello_request(struct s2n_connection *server_conn)
{
    RESULT_ENSURE_REF(server_conn);

    DEFER_CLEANUP(struct s2n_blob message_blob = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_realloc(&message_blob, sizeof(hello_request_msg)));
    RESULT_CHECKED_MEMCPY(message_blob.data, hello_request_msg, message_blob.size);

    /* Send */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    RESULT_GUARD_POSIX(s2n_record_write(server_conn, TLS_HANDSHAKE, &message_blob));
    RESULT_GUARD_POSIX(s2n_flush(server_conn, &blocked));

    /* Cleanup */
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&server_conn->out));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&server_conn->handshake.io));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    static struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Test: Hello request received during the handshake */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Start the handshake.
         * We should be able to receive the hello request in the middle of the handshake. */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                SERVER_HELLO_DONE));
        EXPECT_EQUAL(server_conn->server, &server_conn->initial);

        /* Send a hello request */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* Successfully complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
    }

    /* Test: Hello request received after the handshake */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Send some data */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_OK(s2n_test_send_and_recv(client_conn, server_conn));

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* Send some more data */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_OK(s2n_test_send_and_recv(client_conn, server_conn));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    END_TEST();
}
