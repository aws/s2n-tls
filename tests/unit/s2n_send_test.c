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

#include "api/s2n.h"
#include "tls/s2n_tls.h"

/* s2n_send buffered send test case parameter.
 *
 * If this constant is modified then s2n_expected_buffered_send_fn will likely need
 * to be updated to match.
 *
 * This constant is used to buffer TLS records before they are sent over the socket. This
 * number was chosen at random. */
#define SEND_BUFFER_SIZE 20480

bool s2n_custom_send_fn_called = false;
static uint64_t sent_bytes = 0;
uint32_t s2n_expected_size_call_count = 0;

int s2n_expect_concurrent_error_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_send_fn_called = true;

    s2n_blocked_status blocked = 0;
    ssize_t result = s2n_send(conn, buf, len, &blocked);
    EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_REENTRANCY);
    return result;
}

static int s2n_track_sent_bytes_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    (void) io_context;

    s2n_custom_send_fn_called = true;

    sent_bytes = len;

    return len;
}

static int s2n_track_sent_bytes_partial_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    (void) io_context;

    /* Break loop on second call. */
    if (s2n_custom_send_fn_called) {
        errno = EPIPE;
        return -1;
    }

    int partial_read = len-3;

    sent_bytes = partial_read;
    errno = EAGAIN;

    s2n_custom_send_fn_called = true;

    return partial_read;
}


int s2n_expected_unbuffered_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;

    uint16_t max_record_payload_size = 0;

    EXPECT_OK(s2n_record_max_write_payload_size(conn, &max_record_payload_size));
    EXPECT_EQUAL(max_record_payload_size, 8087);

    uint16_t max_record_fragment_size = 0;

    EXPECT_OK(s2n_record_max_write_size(conn, max_record_payload_size, &max_record_fragment_size));
    EXPECT_EQUAL(max_record_fragment_size, 9116);

    uint32_t expected_send_sizes[] = {8109, 8109, 4328};
    uint32_t expected_stuffer_space_remaining[] = {1007, 1007, 4788};

    /* Drain outbound stuffer like send implementation would. */
    EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->out, len));
    s2n_custom_send_fn_called = true;

    EXPECT_EQUAL(len, expected_send_sizes[s2n_expected_size_call_count]);
    EXPECT_EQUAL(s2n_stuffer_space_remaining(&conn->out), expected_stuffer_space_remaining[s2n_expected_size_call_count]);

    s2n_expected_size_call_count += 1;

    return S2N_SUCCESS;
}

int s2n_expected_buffered_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;

    uint16_t max_record_payload_size = 0;

    EXPECT_OK(s2n_record_max_write_payload_size(conn, &max_record_payload_size));
    EXPECT_EQUAL(max_record_payload_size, 8087);

    uint16_t max_record_fragment_size = 0;

    EXPECT_OK(s2n_record_max_write_size(conn, max_record_payload_size, &max_record_fragment_size));
    EXPECT_EQUAL(max_record_fragment_size, 9116);

    /* Hard coded to make sure that records are not split across multiple sends.
     *
     * This assumes that `s2n_record_max_write_payload_size()` returns 8087. If different
     * sized records are being sent then the constants in this test case need to be adjusted.
     *
     * Expected behavior by record:
     * 1. First 8087 byte record added to conn->out
     * 2. Second 8087 byte record added to conn->out
     * 3. conn->out contains 16218 bytes now. There should be 4262 bytes left in conn->out.
     *    This is larger than the last record so we should flush the connection.
     * 4. conn->out should be flushed now and the entire buffer should be available.
     *    16174 bytes were successfully sent in the first two records, which leave 4306 bytes to
     *    write. Note these sizes are missing the TLS record overhead.
     * 5. Rest of data is sent so we expected a partial record containing 4328 bytes, leaving
     *    16152 bytes in the conn->out stuffer. */
    uint32_t expected_send_sizes[] = {16218, 4328};
    uint32_t expected_stuffer_space_remaining[] = {4262, 16152};

    /* Drain outbound stuffer like send implementation would. */
    EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->out, len));
    s2n_custom_send_fn_called = true;

    EXPECT_EQUAL(len, expected_send_sizes[s2n_expected_size_call_count]);
    EXPECT_EQUAL(s2n_stuffer_space_remaining(&conn->out), expected_stuffer_space_remaining[s2n_expected_size_call_count]);

    s2n_expected_size_call_count += 1;

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_send cannot be called concurrently */
    {
        /* Setup connections */
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Setup bad send callback */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_expect_concurrent_error_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        /* Send test data */
        uint8_t test_data[] = "hello world";
        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(0, conn->wire_bytes_out);
    }

    /* s2n_send tracks conn->wire_bytes_out on send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        EXPECT_EQUAL(0, conn->wire_bytes_out);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_track_sent_bytes_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        /* Send test data */
        uint8_t test_data[] = "hello world";
        s2n_blocked_status blocked = 0;

        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(sizeof(test_data), s2n_send(conn, test_data, sizeof(test_data), &blocked));
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(sent_bytes, conn->wire_bytes_out);
        EXPECT_EQUAL(sent_bytes, s2n_connection_get_wire_bytes_out(conn));
        EXPECT_EQUAL(conn->wire_bytes_out, s2n_connection_get_wire_bytes_out(conn));
    }

    /* s2n_send tracks conn->wire_bytes_out on partial send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        EXPECT_EQUAL(0, conn->wire_bytes_out);

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_track_sent_bytes_partial_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));

        /* Send test data */
        uint8_t test_data[] = "hello world";
        s2n_blocked_status blocked = 0;

        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked), S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(sent_bytes, conn->wire_bytes_out);
        EXPECT_EQUAL(sent_bytes, s2n_connection_get_wire_bytes_out(conn));
    }

    /* s2n_should_flush */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        ssize_t mock_total_message_size = 1 << 15;

        /* Make stuffer larger than the send buffer size so we can test that the conn->send_buffer_size
         * bound is enforced. */
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&conn->out, mock_total_message_size*2));

        uint16_t mock_max_record_fragment_size = 1 << 13;

        /* Unbuffered send should always return true. */
        EXPECT_TRUE(s2n_should_flush(conn, mock_total_message_size, mock_max_record_fragment_size));

        /* Buffered send won't flush an empty connection. */
        conn->send_mode = S2N_BUFFERED_SEND;
        conn->send_buffer_size = mock_total_message_size;
        EXPECT_FALSE(s2n_should_flush(conn, mock_total_message_size, mock_max_record_fragment_size));

        /* If the whole user buffer has been consumed it is time to flush. */
        conn->current_user_data_consumed = mock_total_message_size;
        EXPECT_TRUE(s2n_should_flush(conn, mock_total_message_size, mock_max_record_fragment_size));
        conn->current_user_data_consumed = 0;

        /* If the data available in the out stuffer + the max_write_size is > the send buffer size, we should flush */
        conn->out.write_cursor = (uint32_t)(mock_total_message_size - (mock_max_record_fragment_size/2));
        EXPECT_TRUE(s2n_should_flush(conn, mock_total_message_size, mock_max_record_fragment_size));

        /* If the data available in the out stuffer + the max_write_size is == the send buffer size, we should not flush */
        conn->out.write_cursor = (uint32_t)(mock_total_message_size - mock_max_record_fragment_size);
        EXPECT_FALSE(s2n_should_flush(conn, mock_total_message_size, mock_max_record_fragment_size));

        /* If the data available in the out stuffer + the max_write_size is < the send buffer size, we should not flush */
        conn->out.write_cursor = (uint32_t)(mock_total_message_size - mock_max_record_fragment_size*2);
        EXPECT_FALSE(s2n_should_flush(conn, mock_total_message_size, mock_max_record_fragment_size));

        conn->out.write_cursor = 0;
        /* Resize the out stuffer to always be smaller than the max fragment size. This means that 
         * we will flush because there is not enough space in the stuffer to store another record. */
        EXPECT_SUCCESS(s2n_stuffer_resize(&conn->out, mock_max_record_fragment_size - 1));
        EXPECT_TRUE(s2n_should_flush(conn, mock_total_message_size, mock_max_record_fragment_size));
    }

    /* s2n_send buffered send */
    {
        /* Setup connections */
        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, SEND_BUFFER_SIZE));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Setup bad send callback */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_expected_buffered_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        /* Send test data */
        uint8_t test_data[SEND_BUFFER_SIZE] = {0xB, 0xE, 0xE, 0xF}; /* Rest is 0x0, but we only care about the buffer size */

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        EXPECT_TRUE(s2n_custom_send_fn_called);

        /* Magic number based on buffer sizes. See `s2n_expected_buffered_send_fn` for
         * a breakdown. */
        EXPECT_TRUE(s2n_expected_size_call_count == 2);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* s2n_send unbuffered send */
    {
        s2n_expected_size_call_count = 0;

        /* Setup connections */
        struct s2n_config *config = s2n_config_new();

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Setup bad send callback */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_expected_unbuffered_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        /* Send test data */
        uint8_t test_data[SEND_BUFFER_SIZE] = {0xB, 0xE, 0xE, 0xF}; /* Rest is 0x0, but we only care about the buffer size */

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        EXPECT_TRUE(s2n_custom_send_fn_called);

        /* Magic number based on buffer sizes. See `s2n_expected_unbuffered_send_fn` for
         * a breakdown. */
        EXPECT_TRUE(s2n_expected_size_call_count == 3);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}
