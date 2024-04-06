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

#include "api/s2n.h"
#include "api/unstable/renegotiate.h"
#include "s2n_test.h"
#include "testlib/s2n_ktls_test_utils.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_random.h"

struct s2n_recv_wrapper {
    size_t count;
    s2n_recv_fn *inner_recv;
    void *inner_recv_ctx;
};

static int s2n_counting_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_recv_wrapper *context = (struct s2n_recv_wrapper *) io_context;
    context->count++;
    return context->inner_recv(context->inner_recv_ctx, buf, len);
}

static S2N_RESULT s2n_connection_set_counting_read(struct s2n_connection *reader,
        struct s2n_recv_wrapper *wrapper)
{
    /* We'd need to handle cleanup for managed IO */
    RESULT_ENSURE(!reader->managed_recv_io, S2N_ERR_SAFETY);

    wrapper->inner_recv = reader->recv;
    reader->recv = s2n_counting_read;
    wrapper->inner_recv_ctx = reader->recv_io_context;
    reader->recv_io_context = wrapper;
    wrapper->count = 0;
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t test_data[20] = "hello world";
    const size_t buffer_in_size = S2N_LARGE_FRAGMENT_LENGTH;

    DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

    DEFER_CLEANUP(struct s2n_config *multi_config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(multi_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(multi_config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(multi_config));
    EXPECT_SUCCESS(s2n_config_set_recv_multi_record(multi_config, true));

    /* Test: Read a single record */
    uint32_t test_record_size_val = 0;
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_recv_wrapper counter = { 0 };
        EXPECT_OK(s2n_connection_set_counting_read(server, &counter));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        test_record_size_val = s2n_stuffer_data_available(&io_pair.server_in);
        EXPECT_TRUE(test_record_size_val > sizeof(test_data));

        uint8_t buffer[sizeof(test_data)] = { 0 };
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));
        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
        EXPECT_EQUAL(counter.count, 1);
    }
    const uint32_t test_record_size = test_record_size_val;

    /* Test: Read the handshake */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
    }

    /* Test: Read a record larger than the input buffer */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        client->max_outgoing_fragment_length = UINT16_MAX;
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_recv_wrapper counter = { 0 };
        EXPECT_OK(s2n_connection_set_counting_read(server, &counter));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        DEFER_CLEANUP(struct s2n_blob max_fragment_buffer = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&max_fragment_buffer, S2N_LARGE_FRAGMENT_LENGTH));

        /* Send a record that won't fit in the default input buffer */
        EXPECT_EQUAL(
                s2n_send(client, max_fragment_buffer.data, max_fragment_buffer.size, &blocked),
                max_fragment_buffer.size);
        size_t record_size = s2n_stuffer_data_available(&io_pair.server_in);
        size_t fragment_size = record_size - S2N_TLS_RECORD_HEADER_LENGTH;
        EXPECT_TRUE(fragment_size > buffer_in_size);

        /* Test that the record can be received and the input buffer resized */
        EXPECT_EQUAL(
                s2n_recv(server, max_fragment_buffer.data, max_fragment_buffer.size, &blocked),
                max_fragment_buffer.size);
        EXPECT_TRUE(s2n_stuffer_space_remaining(&server->buffer_in) > fragment_size);
        /* The header fits on the first read, but the rest of the data doesn't.
         * We need a (large) shift + read to get the rest of the data.
         */
        EXPECT_EQUAL(counter.count, 2);

        /* Check that another record can be received afterwards */
        uint8_t buffer[sizeof(test_data)] = { 0 };
        EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
        EXPECT_EQUAL(counter.count, 3);
    }

    /* Test: Read multiple small records */
    for (size_t greedy = 0; greedy <= 1; greedy++) {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        if (greedy) {
            EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
            EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));
        }

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_recv_wrapper counter = { 0 };
        EXPECT_OK(s2n_connection_set_counting_read(server, &counter));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        for (size_t i = 1; i <= sizeof(test_data); i++) {
            EXPECT_EQUAL(s2n_send(client, test_data, i, &blocked), i);
        }

        uint8_t buffer[sizeof(test_data)] = { 0 };
        for (size_t i = 1; i <= sizeof(test_data); i++) {
            EXPECT_EQUAL(s2n_recv(server, buffer, i, &blocked), i);
            EXPECT_BYTEARRAY_EQUAL(buffer, test_data, i);

            if (greedy) {
                /* All our small records combined are smaller than the maximum
                 * TLS record size, so they should all be buffered immediately.
                 * Only one read is ever necessary.
                 */
                EXPECT_EQUAL(counter.count, 1);
            } else {
                /* We call recv twice for every record */
                EXPECT_EQUAL(counter.count, i * 2);
            }
        }

        /* The input buffer size does not change with greedy vs not greedy */
        EXPECT_EQUAL(server->buffer_in.blob.allocated, buffer_in_size);

        /* If all data is consumed, the input buffer can be released */
        EXPECT_SUCCESS(s2n_connection_release_buffers(server));
        EXPECT_EQUAL(server->buffer_in.blob.allocated, 0);
    }

    /* Test: Read multiple small records with "multi_record" enabled */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, multi_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, multi_config));

        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_recv_wrapper counter = { 0 };
        EXPECT_OK(s2n_connection_set_counting_read(server, &counter));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        for (size_t i = 0; i < sizeof(test_data); i++) {
            EXPECT_EQUAL(s2n_send(client, test_data + i, 1, &blocked), 1);
        }

        uint8_t buffer[sizeof(test_data)] = { 0 };
        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
        EXPECT_EQUAL(counter.count, 1);
    }

    /* Test: Read the rest of a partial record */
    for (size_t i = 0; i < test_record_size; i++) {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_recv_wrapper counter = { 0 };
        EXPECT_OK(s2n_connection_set_counting_read(server, &counter));

        size_t expected_count = 0;

        /* Test: manually copy some of the record into the read buffer */
        {
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.server_in), test_record_size);
            EXPECT_SUCCESS(s2n_stuffer_copy(&io_pair.server_in, &server->buffer_in, i));

            uint8_t buffer[sizeof(test_data)] = { 0 };
            EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
            expected_count++;
            EXPECT_EQUAL(counter.count, expected_count);
        }

        /* Test: force the first recv to return partial data */
        {
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.server_in), 0);
            EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.server_in), test_record_size);

            io_pair.server_in.write_cursor -= (test_record_size - i);

            uint8_t buffer[sizeof(test_data)] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server, buffer, sizeof(buffer), &blocked),
                    S2N_ERR_IO_BLOCKED);
            expected_count++;
            /* If the first call returns any data, then a second call is made.
             * The second call blocks. */
            if (i != 0) {
                expected_count++;
            }
            EXPECT_EQUAL(counter.count, expected_count);

            io_pair.server_in.write_cursor += (test_record_size - i);

            EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
            expected_count++;
            EXPECT_EQUAL(counter.count, expected_count);
        }
    }

    /* Test: read a single record one byte at a time */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_recv_wrapper counter = { 0 };
        EXPECT_OK(s2n_connection_set_counting_read(server, &counter));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.server_in), 0);
        EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.server_in), test_record_size);
        io_pair.server_in.write_cursor -= test_record_size;

        size_t expected_count = 0;
        uint8_t buffer[sizeof(test_data)] = { 0 };
        for (size_t i = 1; i < test_record_size; i++) {
            /* Reads no additional data-- just blocks */
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server, buffer, sizeof(buffer), &blocked),
                    S2N_ERR_IO_BLOCKED);
            expected_count++;
            EXPECT_EQUAL(counter.count, expected_count);

            /* Reads the next byte, then blocks again */
            io_pair.server_in.write_cursor++;
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server, buffer, sizeof(buffer), &blocked),
                    S2N_ERR_IO_BLOCKED);
            expected_count += 2;
            EXPECT_EQUAL(counter.count, expected_count);
        }

        /* Reads the final byte and succeeds */
        io_pair.server_in.write_cursor++;
        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
        expected_count++;
        EXPECT_EQUAL(counter.count, expected_count);
    }

    /* Test: Read into a buffer that already contains data from a previous read */
    const struct {
        /* The offset the current record should begin at */
        uint16_t offset;
        /* Assert that shifting occurred if necessary */
        uint16_t final_offset;
        /* Most offsets result in a single read */
        uint8_t reads;
    } test_offsets[] = {
        /* Basic small offsets: single read, no shifting */
        { .offset = 0, .final_offset = test_record_size, .reads = 1 },
        { .offset = 10, .final_offset = 10 + test_record_size, .reads = 1 },
        { .offset = 1000, .final_offset = 1000 + test_record_size, .reads = 1 },
        /* Exactly enough space remaining in the buffer, so no shift or second read.
         * We wipe the buffer after: the extra byte we add to avoid the wipe isn't
         * read because we read exactly as much data as we need.
         */
        {
                .offset = buffer_in_size - test_record_size,
                .final_offset = 0,
                .reads = 1,
        },
        /* If we have enough space in the buffer for the next header,
         * but not enough for the next fragment, then we must still read twice.
         */
        {
                .offset = buffer_in_size - S2N_TLS_RECORD_HEADER_LENGTH,
                .final_offset = test_record_size - S2N_TLS_RECORD_HEADER_LENGTH,
                .reads = 2,
        },
        {
                .offset = buffer_in_size - S2N_TLS_RECORD_HEADER_LENGTH - 1,
                .final_offset = test_record_size - S2N_TLS_RECORD_HEADER_LENGTH,
                .reads = 2,
        },
        /* Not enough space in the buffer for the header or the fragment.
         * We have to shift but don't need a second read.
         */
        { .offset = buffer_in_size - 3, .final_offset = test_record_size, .reads = 1 },
        { .offset = buffer_in_size - 1, .final_offset = test_record_size, .reads = 1 },
        { .offset = buffer_in_size, .final_offset = test_record_size, .reads = 1 },
    };
    for (size_t i = 0; i < s2n_array_len(test_offsets); i++) {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_recv_wrapper counter = { 0 };
        EXPECT_OK(s2n_connection_set_counting_read(server, &counter));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.server_in), test_record_size);
        /* Write one more byte so that we won't wipe buffer_in after the read.
         * This will let us better examine the state of the buffer.
         */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&io_pair.server_in, 0));

        uint16_t offset = test_offsets[i].offset;
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server->buffer_in));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&server->buffer_in, offset));
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&server->buffer_in, offset));
        if (offset < buffer_in_size) {
            /* Preemptively copy one byte of the next record into buffer_in.
             * If we don't do this, we just wipe buffer_in before the read,
             * making this test trivial.
             */
            EXPECT_SUCCESS(s2n_stuffer_copy(&io_pair.server_in, &server->buffer_in, 1));
        }

        uint8_t buffer[sizeof(test_data)] = { 0 };

        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
        EXPECT_EQUAL(counter.count, test_offsets[i].reads);
        uint32_t expected_final_offset = test_offsets[i].final_offset;
        /* If there is an offset, consider the extra byte we added to avoid the final wipe. */
        if (expected_final_offset != 0) {
            expected_final_offset++;
        }
        EXPECT_EQUAL(server->buffer_in.write_cursor, expected_final_offset);
    }

    /* Test: Toggle recv_greedy while reading */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.server_in));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        uint8_t buffer[sizeof(test_data)] = { 0 };

        /* Send many records */
        const size_t records_count = 100;
        for (size_t i = 0; i < records_count; i++) {
            EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
            EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        }

        for (size_t i = 0; i < records_count / 2; i++) {
            EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));
            EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
            EXPECT_TRUE(s2n_stuffer_data_available(&server->buffer_in));

            EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, false));
            EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
        }
    }

    /* Test: s2n_connection_release_buffers with data remaining in buffer_in */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(client, true));
        EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.server_in));

        /* Send two records */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));

        /* Only consume a partial record */
        io_pair.server_in.write_cursor = test_record_size / 2;
        uint8_t buffer[sizeof(test_data)] = { 0 };
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_recv(server, buffer, sizeof(test_data), &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_TRUE(s2n_stuffer_data_available(&server->in));
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_connection_release_buffers(server),
                S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA);

        /* Consume the full first record */
        /* cppcheck-suppress redundantAssignment */
        io_pair.server_in.write_cursor = test_record_size * 2;
        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));

        /* Release buffers */
        EXPECT_TRUE(s2n_stuffer_data_available(&server->buffer_in));
        EXPECT_SUCCESS(s2n_connection_release_buffers(server));
        EXPECT_TRUE(s2n_stuffer_data_available(&server->buffer_in));

        /* Consume the full second record */
        EXPECT_EQUAL(s2n_recv(server, buffer, sizeof(buffer), &blocked), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(buffer, test_data, sizeof(test_data));
    }

    /* Test: s2n_peek_buffered */
    {
        EXPECT_EQUAL(s2n_peek_buffered(NULL), 0);

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, multi_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, multi_config));

        struct {
            uint32_t read_size;
            uint32_t expect_available;
            uint32_t expect_buffered;
        } test_cases[] = {
            {
                    .read_size = 1,
                    .expect_available = sizeof(test_data) - 1,
                    .expect_buffered = test_record_size,
            },
            {
                    .read_size = sizeof(test_data) - 1,
                    .expect_available = 1,
                    .expect_buffered = test_record_size,
            },
            {
                    .read_size = sizeof(test_data),
                    .expect_available = 0,
                    .expect_buffered = test_record_size,
            },
            {
                    .read_size = sizeof(test_data) + 1,
                    .expect_available = sizeof(test_data) - 1,
                    .expect_buffered = 0,
            },
        };
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.server_in));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t buffer[sizeof(test_data) * 2] = { 0 };

            EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));
            EXPECT_EQUAL(s2n_send(client, test_data, sizeof(test_data), &blocked), sizeof(test_data));

            uint32_t read_size = test_cases[i].read_size;
            EXPECT_SUCCESS(s2n_connection_set_recv_buffering(server, true));
            EXPECT_EQUAL(s2n_recv(server, buffer, read_size, &blocked), read_size);
            EXPECT_EQUAL(s2n_peek_buffered(server), test_cases[i].expect_buffered);
            EXPECT_EQUAL(s2n_peek(server), test_cases[i].expect_available);

            EXPECT_SUCCESS(s2n_connection_wipe(client));
            EXPECT_SUCCESS(s2n_connection_wipe(server));
        }
    }

    END_TEST();
}
