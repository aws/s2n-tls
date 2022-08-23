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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

int s2n_ticket_count_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    uint8_t *count = (uint8_t *) ctx;
    (*count)++;
    return S2N_SUCCESS;
}

S2N_RESULT s2n_test_enable_tickets(struct s2n_config *config)
{
    RESULT_ENSURE_REF(config);

    uint8_t ticket_key_name[16] = "key name";
    uint8_t ticket_key[] = "key data";

    uint64_t current_time = 0;
    RESULT_GUARD_POSIX(config->wall_clock(config->sys_clock_ctx, &current_time));

    RESULT_GUARD_POSIX(s2n_config_set_session_tickets_onoff(config, 1));
    RESULT_GUARD_POSIX(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                    ticket_key, sizeof(ticket_key), current_time/ONE_SEC_IN_NANOS));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_init_client_and_server(struct s2n_config *config,
        struct s2n_connection *client_conn, struct s2n_connection *server_conn,
        struct s2n_test_io_pair *io_pair)
{
    RESULT_ENSURE_REF(config);
    RESULT_GUARD(s2n_test_enable_tickets(config));

    RESULT_ENSURE_REF(client_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, config));
    RESULT_GUARD(s2n_connection_set_secrets(client_conn));

    RESULT_ENSURE_REF(server_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(server_conn, config));
    RESULT_GUARD(s2n_connection_set_secrets(server_conn));

    RESULT_ENSURE_REF(io_pair);
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(io_pair));
    EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, io_pair));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_write_nst_messages(struct s2n_connection *conn, struct s2n_stuffer *messages, size_t message_count)
{
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(messages, 0));
    for (size_t i = 0; i < message_count; i++) {
        RESULT_GUARD(s2n_tls13_server_nst_write(conn, messages));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_send_nst_records(struct s2n_connection *conn, struct s2n_stuffer *messages, size_t record_count)
{
    size_t fragment_size = (s2n_stuffer_data_available(messages) / (record_count));
    if (s2n_stuffer_data_available(messages) % record_count != 0) {
        fragment_size++;
    }

    DEFER_CLEANUP(struct s2n_blob record_data = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&record_data, fragment_size));

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint32_t remaining = 0;
    while((remaining = s2n_stuffer_data_available(messages)) > 0){
        record_data.size = MIN(record_data.size, remaining);
        RESULT_GUARD_POSIX(s2n_stuffer_read(messages, &record_data));
        RESULT_ENSURE_EQ(s2n_record_write(conn, TLS_HANDSHAKE, &record_data), record_data.size);
        RESULT_GUARD_POSIX(s2n_flush(conn, &blocked));
    };

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_seq_num(uint8_t *seq_num_bytes, uint64_t *seq_num)
{
    struct s2n_blob seq_num_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&seq_num_blob, seq_num_bytes, S2N_TLS_SEQUENCE_NUM_LEN));

    struct s2n_stuffer seq_num_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&seq_num_stuffer, &seq_num_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&seq_num_stuffer, S2N_TLS_SEQUENCE_NUM_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint64(&seq_num_stuffer, seq_num));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_recv(struct s2n_config *config,
        struct s2n_connection *client_conn, struct s2n_connection *server_conn,
        uint8_t expected_messages, uint8_t expected_records)
{
    uint8_t tickets_count = 0;
    RESULT_GUARD_POSIX(s2n_config_set_session_ticket_cb(config, s2n_ticket_count_cb, &tickets_count));

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint8_t app_data[1] = { 0 };
    RESULT_ENSURE_EQ(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
    RESULT_ENSURE_EQ(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));

    /* Verify post-handshake message count.
     * We should have received one ticket for each message. */
    RESULT_ENSURE_EQ(tickets_count, expected_messages);

    /* Verify record count.
     * We can get the number of records received by the client
     * by looking at the client's view of the server's sequence number.
     */
    uint64_t seq_num = 0;
    RESULT_GUARD(s2n_get_seq_num(client_conn->secure.server_sequence_number, &seq_num));
    /*
     * We should have received one more record than "expected",
     * because we sent and received one ApplicationData record.
     */
    RESULT_ENSURE_EQ(seq_num, expected_records + 1);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_basic_recv_test(uint8_t expected_messages, uint8_t expected_records)
{
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    RESULT_GUARD(s2n_test_init_client_and_server(config, client_conn, server_conn, &io_pair));

    DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
    RESULT_GUARD(s2n_test_write_nst_messages(server_conn, &messages, expected_messages));
    RESULT_GUARD(s2n_test_send_nst_records(server_conn, &messages, expected_records));
    RESULT_GUARD(s2n_test_recv(config, client_conn, server_conn, expected_messages, expected_records));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Recv a single record with a single post-handshake message */
    {
        const uint8_t expected_messages = 1;
        const uint8_t expected_records = 1;
        EXPECT_OK(s2n_basic_recv_test(expected_messages, expected_records));
    }

    /* Recv a single record with multiple post-handshake messages */
    {
        const uint8_t expected_messages = 5;
        const uint8_t expected_records = 1;
        EXPECT_OK(s2n_basic_recv_test(expected_messages, expected_records));
    }

    /* Recv multiple records with a single fragmented post-handshake message */
    {
        /* Split message across two records */
        {
            const uint8_t expected_messages = 1;
            const uint8_t expected_records = 2;
            EXPECT_OK(s2n_basic_recv_test(expected_messages, expected_records));
        }

        /* Split message across many records */
        {
            const uint8_t expected_messages = 1;
            const uint8_t expected_records = 5;
            EXPECT_OK(s2n_basic_recv_test(expected_messages, expected_records));
        }

        /* Split message into fragments smaller than the message header */
        {
            const uint8_t expected_messages = 1;

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_OK(s2n_test_init_client_and_server(config, client_conn, server_conn, &io_pair));

            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_write_nst_messages(server_conn, &messages, expected_messages));

            /* Split the messages into single byte fragments,
             * ensuring that we have to read multiple records to reconstruct the header.
             */
            uint32_t expected_records = s2n_stuffer_data_available(&messages);
            EXPECT_OK(s2n_test_send_nst_records(server_conn, &messages, expected_records));

            EXPECT_OK(s2n_test_recv(config, client_conn, server_conn, expected_messages, expected_records));
        }
    }

    /* Recv multiple records with multiple post-handshake messages */
    {
        const uint8_t expected_messages = 10;
        const uint8_t expected_records = 3;
        EXPECT_OK(s2n_basic_recv_test(expected_messages, expected_records));
    }

    /* Recv blocks while reading fragmented post-handshake messages */
    {
        const uint8_t expected_messages = 1;
        const uint8_t expected_records = 2;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_OK(s2n_test_init_client_and_server(config, client_conn, server_conn, &io_pair));

        /* Use stuffer io to control blocking */
        DEFER_CLEANUP(struct s2n_stuffer server_in, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer client_in, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_in, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &client_in, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_in, &server_in, client_conn));

        uint8_t tickets_count = 0;
        EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_ticket_count_cb, &tickets_count));

        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_write_nst_messages(server_conn, &messages, expected_messages));
        EXPECT_OK(s2n_test_send_nst_records(server_conn, &messages, expected_records));
        uint32_t messages_len = s2n_stuffer_data_available(&client_in);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        uint8_t app_data[1] = { 0 };
        EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));

        /* Drop some bytes off the end of the input so that
         * reading the last handshake record will block.
         */
        uint32_t write_cursor = client_in.write_cursor;
        client_in.write_cursor = messages_len - 1;

        uint64_t seq_num = 0;
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        EXPECT_OK(s2n_get_seq_num(client_conn->secure.server_sequence_number, &seq_num));

        /* One record successfully read, but not a full message yet */
        EXPECT_EQUAL(seq_num, 1 /* 1 handshake */ );
        EXPECT_EQUAL(tickets_count, 0);

        /* Restore the full input to unblock the connection */
        // cppcheck-suppress redundantAssignment
        client_in.write_cursor = write_cursor;

        EXPECT_EQUAL(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_OK(s2n_get_seq_num(client_conn->secure.server_sequence_number, &seq_num));

        /* Both records read and the message processed */
        EXPECT_EQUAL(seq_num, 3 /* 2 handshake + 1 app data */);
        EXPECT_EQUAL(tickets_count, 1);
    }

    /* Test conn->post_handshake.in memory management */
    {
        const uint8_t expected_messages = 3;
        const uint8_t expected_records = 2;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_OK(s2n_test_init_client_and_server(config, client_conn, server_conn, &io_pair));

        /* Initially uninitialized, but growable */
        EXPECT_EQUAL(client_conn->post_handshake.in.blob.data, NULL);
        EXPECT_EQUAL(client_conn->post_handshake.in.blob.size, 0);
        EXPECT_EQUAL(client_conn->post_handshake.in.growable, true);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        uint8_t app_data[1] = { 0 };
        uint64_t seq_num = 0;

        /* Allocated for fragmented handshake message */
        {
            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_write_nst_messages(server_conn, &messages, expected_messages));
            EXPECT_OK(s2n_test_send_nst_records(server_conn, &messages, expected_records));

            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_OK(s2n_get_seq_num(client_conn->secure.server_sequence_number, &seq_num));
            EXPECT_EQUAL(seq_num, expected_records);

            EXPECT_NOT_EQUAL(client_conn->post_handshake.in.blob.size, 0);
        }

        /* Kept after handshake message / reused for multiple handshake messages */
        {
            uint8_t *old_mem = client_conn->post_handshake.in.blob.data;

            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_write_nst_messages(server_conn, &messages, expected_messages));
            EXPECT_OK(s2n_test_send_nst_records(server_conn, &messages, expected_records));

            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_OK(s2n_get_seq_num(client_conn->secure.server_sequence_number, &seq_num));
            EXPECT_EQUAL(seq_num, expected_records * 2);

            EXPECT_NOT_EQUAL(client_conn->post_handshake.in.blob.size, 0);
            EXPECT_EQUAL(old_mem, client_conn->post_handshake.in.blob.data);
        }

        /* Freed after successful s2n_recv call */
        {
            EXPECT_EQUAL(s2n_send(server_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), sizeof(app_data));
            EXPECT_EQUAL(client_conn->post_handshake.in.blob.size, 0);
        }
    }

    /*
     *= https://tools.ietf.org/rfc/rfc8446#section-5.1
     *= type=test
     *#    -  Handshake messages MUST NOT be interleaved with other record
     *#       types.  That is, if a handshake message is split over two or more
     *#       records, there MUST NOT be any other records between them.
     */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_OK(s2n_test_init_client_and_server(config, client_conn, server_conn, &io_pair));

        uint8_t tickets_count = 0;
        EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_ticket_count_cb, &tickets_count));

        DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_write_nst_messages(server_conn, &messages, 1));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Send a fragment of a post-handshake message */
        DEFER_CLEANUP(struct s2n_blob record_data = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_realloc(&record_data, 10));
        EXPECT_SUCCESS(s2n_stuffer_read(&messages, &record_data));
        EXPECT_EQUAL(s2n_record_write(server_conn, TLS_HANDSHAKE, &record_data), record_data.size);
        EXPECT_SUCCESS(s2n_flush(server_conn, &blocked));

        /* Send Application Data.
         * (Just reuse the last data we sent, but with a different record type) */
        EXPECT_EQUAL(s2n_record_write(server_conn, TLS_APPLICATION_DATA, &record_data), record_data.size);
        EXPECT_SUCCESS(s2n_flush(server_conn, &blocked));

        /* Send the rest of the post-handshake message */
        EXPECT_SUCCESS(s2n_realloc(&record_data, s2n_stuffer_data_available(&messages)));
        EXPECT_SUCCESS(s2n_stuffer_read(&messages, &record_data));
        EXPECT_EQUAL(s2n_record_write(server_conn, TLS_HANDSHAKE, &record_data), record_data.size);
        EXPECT_SUCCESS(s2n_flush(server_conn, &blocked));

        uint64_t seq_num = 0;
        uint8_t app_data[1] = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(client_conn, app_data, sizeof(app_data), &blocked), S2N_ERR_BAD_MESSAGE);
        EXPECT_OK(s2n_get_seq_num(client_conn->secure.server_sequence_number, &seq_num));

        /* The error occurred when processing the unexpected application data record,
         * so we've read both the first handshake record and the application data record. */
        EXPECT_EQUAL(seq_num, 2);
        EXPECT_EQUAL(tickets_count, 0);
    }

    END_TEST();
}
