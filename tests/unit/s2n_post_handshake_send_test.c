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

#include <math.h>
#include <stdlib.h>

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

#define S2N_FRAG_LEN_SMALLER_THAN_NST 50

static S2N_RESULT s2n_get_expected_record_count(uint32_t nst_size, uint32_t fragment_size, uint8_t tickets_to_send,
        uint64_t *expected_record_count)
{
    uint32_t app_data_records = 1;
    uint32_t records_per_nst = ceil((1.0 * nst_size) / fragment_size);
    uint32_t nst_records = records_per_nst * tickets_to_send;
    *expected_record_count = app_data_records + nst_records;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_get_actual_record_count(uint8_t *cur_seq_num_bytes,
        uint64_t *last_seq_num, uint64_t *actual_record_count)
{
    uint64_t cur_seq_num = 0;
    struct s2n_blob blob = { 0 };
    struct s2n_stuffer stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&blob, cur_seq_num_bytes, S2N_TLS_SEQUENCE_NUM_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_init(&stuffer, &blob));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&stuffer, S2N_TLS_SEQUENCE_NUM_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint64(&stuffer, &cur_seq_num));

    *actual_record_count = cur_seq_num - *last_seq_num;
    *last_seq_num = cur_seq_num;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_get_nst_message_size(struct s2n_connection *conn, uint32_t *size)
{
    DEFER_CLEANUP(struct s2n_stuffer nst_message = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&nst_message, 0));
    RESULT_GUARD(s2n_tls13_server_nst_write(conn, &nst_message));
    *size = s2n_stuffer_data_available(&nst_message);
    EXPECT_TRUE(*size > S2N_FRAG_LEN_SMALLER_THAN_NST);
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    /* These tests require sending tickets.
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
        TLS_HANDSHAKE_HEADER_LENGTH,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
        S2N_FRAG_LEN_SMALLER_THAN_NST,
        S2N_DEFAULT_FRAGMENT_LENGTH,
        S2N_TLS_MAXIMUM_FRAGMENT_LENGTH,
    };

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    const uint8_t send_data[1] = { 'k' };
    const uint8_t tickets_to_send = 3;

    /* Test: send fragmented post-handshake message (NewSessionTicket) */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
        EXPECT_OK(s2n_connection_set_secrets(server_conn));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));
        EXPECT_OK(s2n_connection_set_secrets(client_conn));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

        /* Calculate the size of the NewSessionTicket message */
        uint32_t nst_size = 0;
        EXPECT_OK(s2n_get_nst_message_size(server_conn, &nst_size));

        /* Test: the messages are fragmented into the number of records expected */
        uint64_t write_seq_num = 0;
        for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
            const uint32_t fragment_size = fragment_sizes[frag_i];

            server_conn->max_outgoing_fragment_length = fragment_size;
            server_conn->tickets_sent = 0;
            server_conn->tickets_to_send = tickets_to_send;

            EXPECT_SUCCESS(s2n_send(server_conn, send_data, sizeof(send_data), &blocked));
            EXPECT_EQUAL(server_conn->tickets_sent, tickets_to_send);
            EXPECT_TRUE(s2n_stuffer_is_freed(&server_conn->handshake.io));

            uint64_t actual_record_count = 0;
            uint64_t expected_record_count = 0;
            uint8_t *seq_num = server_conn->server->server_sequence_number;
            EXPECT_OK(s2n_get_actual_record_count(seq_num, &write_seq_num, &actual_record_count));
            EXPECT_OK(s2n_get_expected_record_count(nst_size, fragment_size, tickets_to_send, &expected_record_count));
            EXPECT_EQUAL(actual_record_count, expected_record_count);
        }

        /* Test: the full messages can be parsed by the client */
        uint64_t read_seq_num = 0;
        for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
            const uint32_t fragment_size = fragment_sizes[frag_i];

            uint8_t recv_data[sizeof(send_data)] = { 0 };
            EXPECT_SUCCESS(s2n_recv(client_conn, recv_data, sizeof(recv_data), &blocked));
            EXPECT_BYTEARRAY_EQUAL(send_data, recv_data, sizeof(recv_data));

            uint64_t actual_record_count = 0;
            uint64_t expected_record_count = 0;
            uint8_t *seq_num = client_conn->server->server_sequence_number;
            EXPECT_OK(s2n_get_actual_record_count(seq_num, &read_seq_num, &actual_record_count));
            EXPECT_OK(s2n_get_expected_record_count(nst_size, fragment_size, tickets_to_send, &expected_record_count));
            EXPECT_EQUAL(actual_record_count, expected_record_count);
        }
    };

    /* Test: send fragmented post-handshake messages (NewSessionTicket) when IO blocks  */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
        EXPECT_OK(s2n_connection_set_secrets(server_conn));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));
        EXPECT_OK(s2n_connection_set_secrets(client_conn));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

        /* Calculate the size of the NewSessionTicket message */
        uint32_t nst_size = 0;
        EXPECT_OK(s2n_get_nst_message_size(server_conn, &nst_size));

        /* Free the client_in (server_out) so that we can later trigger blocking */
        struct s2n_stuffer *server_out = &io_pair.client_in;
        EXPECT_SUCCESS(s2n_stuffer_free(server_out));
        EXPECT_SUCCESS(s2n_stuffer_alloc(server_out, 0));

        /* Test: the messages can be sent despite constant IO blocking */
        uint64_t write_seq_num = 0;
        for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
            const uint32_t fragment_size = fragment_sizes[frag_i];

            server_conn->max_outgoing_fragment_length = fragment_size;
            server_conn->tickets_sent = 0;
            server_conn->tickets_to_send = tickets_to_send;

            while (s2n_send(server_conn, send_data, sizeof(send_data), &blocked) < S2N_SUCCESS) {
                EXPECT_EQUAL(s2n_errno, S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

                /* Resize server_out.
                 * However, we don't want s2n_send to resize the buffer itself,
                 * so we need to lie about the stuffer not being growable.
                 */
                server_out->growable = true;
                size_t existing_size = s2n_stuffer_data_available(server_out);
                size_t new_data_size = s2n_stuffer_data_available(&server_conn->out);
                EXPECT_SUCCESS(s2n_stuffer_resize(server_out, existing_size + new_data_size));
                server_out->growable = false;
            }
            EXPECT_EQUAL(server_conn->tickets_sent, tickets_to_send);
            EXPECT_TRUE(s2n_stuffer_is_freed(&server_conn->handshake.io));

            uint64_t actual_record_count = 0;
            uint64_t expected_record_count = 0;
            uint8_t *seq_num = server_conn->server->server_sequence_number;
            EXPECT_OK(s2n_get_actual_record_count(seq_num, &write_seq_num, &actual_record_count));
            EXPECT_OK(s2n_get_expected_record_count(nst_size, fragment_size, tickets_to_send, &expected_record_count));
            EXPECT_EQUAL(actual_record_count, expected_record_count);
        }

        /* Test: the full messages can be parsed by the client */
        uint64_t read_seq_num = 0;
        for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
            const uint32_t fragment_size = fragment_sizes[frag_i];

            uint8_t recv_data[sizeof(send_data)] = { 0 };
            EXPECT_SUCCESS(s2n_recv(client_conn, recv_data, sizeof(recv_data), &blocked));
            EXPECT_BYTEARRAY_EQUAL(send_data, recv_data, sizeof(recv_data));

            uint64_t actual_record_count = 0;
            uint64_t expected_record_count = 0;
            uint8_t *seq_num = client_conn->server->server_sequence_number;
            EXPECT_OK(s2n_get_actual_record_count(seq_num, &read_seq_num, &actual_record_count));
            EXPECT_OK(s2n_get_expected_record_count(nst_size, fragment_size, tickets_to_send, &expected_record_count));
            EXPECT_EQUAL(actual_record_count, expected_record_count);
        }
    };

    END_TEST();
}
