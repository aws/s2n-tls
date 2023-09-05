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

#include <sys/param.h>
#include <sys/socket.h>

#include "api/unstable/renegotiate.h"
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

#define S2N_TEST_MESSAGE_COUNT 5

int s2n_key_update_write(struct s2n_blob *out);

size_t tickets_count = 0;
static int s2n_ticket_count_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    tickets_count++;
    return S2N_SUCCESS;
}

size_t hello_request_count = 0;
static int s2n_hello_request_cb(struct s2n_connection *conn, void *ctx, s2n_renegotiate_response *response)
{
    hello_request_count++;
    *response = S2N_RENEGOTIATE_IGNORE;
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_test_send_records(struct s2n_connection *conn, struct s2n_stuffer messages, uint32_t fragment_size)
{
    conn->max_outgoing_fragment_length = fragment_size;

    DEFER_CLEANUP(struct s2n_blob record_data = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&record_data, fragment_size));

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint32_t remaining = 0;
    while ((remaining = s2n_stuffer_data_available(&messages)) > 0) {
        record_data.size = MIN(record_data.size, remaining);
        RESULT_GUARD_POSIX(s2n_stuffer_read(&messages, &record_data));
        RESULT_GUARD(s2n_record_write(conn, TLS_HANDSHAKE, &record_data));
        RESULT_GUARD_POSIX(s2n_flush(conn, &blocked));
    };

    return S2N_RESULT_OK;
}

/*
 * Verify that the receiver can receive a byte sent by the sender.
 * In the process, we also verify that the receiver can receive all previous
 * data sent by the sender, since TCP / TLS messages have a guaranteed order.
 */
static S2N_RESULT s2n_test_basic_recv(struct s2n_connection *sender, struct s2n_connection *receiver)
{
    uint8_t app_data[1] = { 0 };
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    int send_ret = s2n_send(sender, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(send_ret);
    RESULT_ENSURE_EQ(send_ret, sizeof(app_data));

    /* Reset all counters */
    RESULT_GUARD(s2n_mem_test_wipe_callbacks());
    tickets_count = 0;
    hello_request_count = 0;

    int recv_ret = s2n_recv(receiver, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(recv_ret);
    RESULT_ENSURE_EQ(recv_ret, sizeof(app_data));

    return S2N_RESULT_OK;
}

/* Like s2n_test_basic_recv,
 * but we make only one byte of data available at a time.
 * This forces us to call s2n_recv repeatedly and verifies that s2n_recv
 * can resume across s2n_recv calls while handling fragmented post-handshake messages.
 */
static S2N_RESULT s2n_test_blocking_recv(struct s2n_connection *sender, struct s2n_connection *receiver,
        struct s2n_test_io_stuffer_pair *io_pair)
{
    uint8_t app_data[1] = { 0 };
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    int send_ret = s2n_send(sender, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(send_ret);
    RESULT_ENSURE_EQ(send_ret, sizeof(app_data));

    /* Reset all counters */
    RESULT_GUARD(s2n_mem_test_wipe_callbacks());
    tickets_count = 0;
    hello_request_count = 0;

    /* Modify the stuffer's write_cursor to make only one byte
     * of the socket / input data available at a time.
     */
    struct s2n_stuffer *in = &io_pair->client_in;
    if (receiver->mode == S2N_SERVER) {
        in = &io_pair->server_in;
    }
    uint32_t *write_cursor = &in->write_cursor;
    uint32_t *read_cursor = &in->read_cursor;
    RESULT_ENSURE_GT(write_cursor, read_cursor);
    uint32_t saved_write_cursor = *write_cursor;
    RESULT_ENSURE_GT(saved_write_cursor, 0);
    *write_cursor = *read_cursor + 1;

    while (s2n_recv(receiver, app_data, sizeof(app_data), &blocked) < 0) {
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        EXPECT_EQUAL(s2n_errno, S2N_ERR_IO_BLOCKED);
        (*write_cursor)++;
        RESULT_ENSURE_LTE(*write_cursor, saved_write_cursor);
    }
    RESULT_ENSURE_EQ(*write_cursor, saved_write_cursor);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_init_sender_and_receiver(struct s2n_config *config,
        struct s2n_connection *sender, struct s2n_connection *receiver,
        struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_GUARD_POSIX(s2n_connection_set_config(sender, config));
    RESULT_GUARD_POSIX(s2n_connection_set_all_protocol_versions(sender, S2N_TLS13));
    RESULT_GUARD(s2n_connection_set_secrets(sender));
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(sender, S2N_SELF_SERVICE_BLINDING));

    RESULT_GUARD_POSIX(s2n_connection_set_config(receiver, config));
    RESULT_GUARD_POSIX(s2n_connection_set_all_protocol_versions(receiver, S2N_TLS13));
    RESULT_GUARD(s2n_connection_set_secrets(receiver));
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(receiver, S2N_SELF_SERVICE_BLINDING));

    RESULT_GUARD(s2n_io_stuffer_pair_init(io_pair));
    if (sender->mode == S2N_SERVER) {
        RESULT_GUARD(s2n_connections_set_io_stuffer_pair(receiver, sender, io_pair));
    } else {
        RESULT_GUARD(s2n_connections_set_io_stuffer_pair(sender, receiver, io_pair));
    }

    /* Send and receive to initialize io buffers */
    EXPECT_OK(s2n_test_basic_recv(sender, receiver));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t unknown_message_type = UINT8_MAX;
    const uint32_t test_large_message_size = 3001;

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_ticket_count_cb, NULL));
    EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, s2n_hello_request_cb, NULL));

    /* Some tests require sending and receiving tickets.
     * Setup the config to handle tickets, but don't send any by default.
     */
    uint8_t ticket_key_name[16] = "key name";
    uint8_t ticket_key[] = "key data";
    uint64_t current_time = 0;
    EXPECT_SUCCESS(config->wall_clock(config->sys_clock_ctx, &current_time));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, sizeof(ticket_key_name),
            ticket_key, sizeof(ticket_key), current_time / ONE_SEC_IN_NANOS));
    config->initial_tickets_to_send = 0;

    const uint32_t fragment_sizes[] = {
        1,
        2,
        S2N_MIN_SEND_BUFFER_FRAGMENT_SIZE,
        TLS_HANDSHAKE_HEADER_LENGTH,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
        S2N_DEFAULT_FRAGMENT_LENGTH,
        S2N_TLS_MAXIMUM_FRAGMENT_LENGTH,
    };
    const uint8_t modes[] = { S2N_CLIENT, S2N_SERVER };

    /* Test: client and server receive small post-handshake messages (KeyUpdates) */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

            /* Write KeyUpdate message */
            struct s2n_stuffer message = { 0 };
            DEFER_CLEANUP(struct s2n_blob message_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&message_blob, S2N_KEY_UPDATE_MESSAGE_SIZE));
            for (size_t i = 0; i < S2N_TEST_MESSAGE_COUNT; i++) {
                EXPECT_SUCCESS(s2n_key_update_write(&message_blob));
                EXPECT_SUCCESS(s2n_stuffer_init(&message, &message_blob));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, S2N_KEY_UPDATE_MESSAGE_SIZE));

                /* The TLS1.3 RFC says "Handshake messages MUST NOT span key changes".
                 * Because KeyUpdate messages trigger key changes, we cannot include multiple in one record.
                 * We must send individual KeyUpdate messages.
                 */
                EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));

                /* Update the traffic keys for the next records */
                EXPECT_SUCCESS(s2n_update_application_traffic_keys(sender, sender->mode, SENDING));
            }

            /*
             * We have no mechanism to count KeyUpdates, but we can assume they are processed
             * if we successfully decrypt all records. If they were not processed,
             * then we would try to use the wrong key to decrypt the next record.
             */
            DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
            EXPECT_OK(s2n_test_basic_recv(sender, receiver));
            EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
        }
    }

    /* Test: client receives large post-handshake messages (NewSessionTickets)
     *
     * There is no server version of this test because there are no large post-handshake messages
     * valid for the server to accept.
     */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, server, client, &io_pair));

        /* Write NewSessionTicket message */
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        for (size_t i = 0; i < S2N_TEST_MESSAGE_COUNT; i++) {
            server->tickets_to_send++;
            EXPECT_OK(s2n_tls13_server_nst_write(server, &messages));
        }

        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_basic_recv(server, client));
        EXPECT_EQUAL(tickets_count, S2N_TEST_MESSAGE_COUNT);

        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_blocking_recv(server, client, &io_pair));
        EXPECT_EQUAL(tickets_count, S2N_TEST_MESSAGE_COUNT);
    }

    /* Test: client receives large post-handshake messages of different sizes (NewSessionTickets)
     *
     * There is no server version of this test because there are no large post-handshake messages
     * valid for the server to accept.
     */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, server, client, &io_pair));
        server->server_max_early_data_size = 10;

        size_t total_size = 0;
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        for (size_t i = 0; i < 3; i++) {
            /* Write a basic NewSessionTicket */
            server->server_max_early_data_size_overridden = false;
            server->tickets_to_send++;
            EXPECT_OK(s2n_tls13_server_nst_write(server, &messages));
            size_t min_length = s2n_stuffer_data_available(&messages) - total_size;
            total_size += min_length;

            /* Write a NewSesionTicket with early data enabled
             * so that the early_data_indication extension is included
             * and the message is therefore longer.
             */
            server->server_max_early_data_size_overridden = true;
            server->tickets_to_send++;
            EXPECT_OK(s2n_tls13_server_nst_write(server, &messages));
            size_t max_length = s2n_stuffer_data_available(&messages) - total_size;
            EXPECT_TRUE(max_length > min_length);
            total_size += max_length;
        }

        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_basic_recv(server, client));
        EXPECT_EQUAL(tickets_count, server->tickets_to_send);

        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_blocking_recv(server, client, &io_pair));
        EXPECT_EQUAL(tickets_count, server->tickets_to_send);
    }

    /* Test: server rejects known, invalid post-handshake messages (NewSessionTickets)
     *
     * There is no client version of this test because the client accepts all supported
     * post-handshake messages.
     */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, client, server, &io_pair));

        /* Send NewSessionTicket message */
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        client->tickets_to_send = 1;
        EXPECT_OK(s2n_tls13_server_nst_write(client, &messages));
        EXPECT_OK(s2n_test_send_records(client, messages, fragment_size));

        DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(client, server), S2N_ERR_BAD_MESSAGE);
        EXPECT_EQUAL(tickets_count, 0);
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
    }

    /* Test: server rejects fragmented post-handshake message (KeyUpdate) with an invalid size
     *
     * This response is unique to the server because we want to prevent a malicious
     * client from forcing the server to allocate large amounts of memory.
     *
     * While we could extend the same validation to the client, the client accepts
     * a variable-sized message (NewSessionTicket) so can't really be protected.
     */
    {
        /* This test is only interesting if the message is fragmented */
        uint32_t fragment_size = 2;

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, client, server, &io_pair));

        /* Write large KeyUpdate messages */
        DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, TLS_KEY_UPDATE));
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, test_large_message_size));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, test_large_message_size));
        EXPECT_OK(s2n_test_send_records(client, message, fragment_size));
        EXPECT_SUCCESS(s2n_update_application_traffic_keys(client, client->mode, SENDING));

        DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(client, server), S2N_ERR_BAD_MESSAGE);

        /* No post-handshake message should trigger the server to allocate memory */
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
    };

    /* Test: client receives empty post-handshake messages (HelloRequests)
     *
     * There is no server version of this test because there are no empty post-handshake messages
     * valid for the server to accept.
     */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, server, client, &io_pair));

        /* HelloRequests are ignored if secure_renegotiation isn't set */
        client->secure_renegotiation = true;

        /* Write HelloRequest messages */
        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
        for (size_t i = 0; i < S2N_TEST_MESSAGE_COUNT; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&messages, TLS_HELLO_REQUEST));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&messages, 0));
        }

        DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));

        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_basic_recv(server, client));
        EXPECT_EQUAL(hello_request_count, S2N_TEST_MESSAGE_COUNT);
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));

        EXPECT_OK(s2n_test_send_records(server, messages, fragment_size));
        EXPECT_OK(s2n_test_blocking_recv(server, client, &io_pair));
        EXPECT_EQUAL(hello_request_count, S2N_TEST_MESSAGE_COUNT);
        EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
    }

    /* Test: client and server reject known, invalid messages (ClientHellos) */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

            /* Send fake ClientHello messages */
            DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, TLS_HANDSHAKE_HEADER_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, TLS_CLIENT_HELLO));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, test_large_message_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, test_large_message_size));
            EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));

            DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
            EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(sender, receiver), S2N_ERR_BAD_MESSAGE);

            /* No post-handshake message should trigger the server to allocate memory */
            if (mode == S2N_SERVER) {
                EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
            }
        }
    }

    /* Test: client and server reject unknown messages */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

            /* Send unknown message */
            DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, unknown_message_type));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, test_large_message_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&message, test_large_message_size));
            EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));

            DEFER_CLEANUP(struct s2n_mem_test_cb_scope mem_ctx = { 0 }, s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&mem_ctx));
            EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(sender, receiver), S2N_ERR_BAD_MESSAGE);

            /* No post-handshake message should trigger the server to allocate memory */
            if (mode == S2N_SERVER) {
                EXPECT_OK(s2n_mem_test_assert_malloc_count(0));
            }
        }
    }

    /**
     *= https://tools.ietf.org/rfc/rfc8446#section-5.1
     *= type=test
     *#    -  Handshake messages MUST NOT be interleaved with other record
     *#       types.  That is, if a handshake message is split over two or more
     *#       records, there MUST NOT be any other records between them.
     */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        uint8_t mode = modes[mode_i];

        /* This test is only interesting if the message is fragmented */
        uint32_t fragment_size = 2;

        DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_test_init_sender_and_receiver(config, sender, receiver, &io_pair));

        /* Write a partial message */
        DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&message, TLS_KEY_UPDATE));
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&message, S2N_KEY_UPDATE_LENGTH));
        /* Don't write the actual message body -- we want the message to be incomplete */

        /* Verify we can't receive the records: s2n_test_send_records does not send
         * the complete handshake message, so we receive the application data sent by
         * s2n_test_basic_recv in the middle of the handshake message.
         */
        EXPECT_OK(s2n_test_send_records(sender, message, fragment_size));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_basic_recv(sender, receiver), S2N_ERR_BAD_MESSAGE);
    }

    END_TEST();
}
