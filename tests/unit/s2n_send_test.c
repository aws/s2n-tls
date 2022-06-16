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

#define SEND_BUFFER_SIZE 20480

struct s2n_buffered_send_test_callback_params {
    uint32_t writes;
    uint32_t *consumed_user_data_sizes;
    size_t consumed_user_data_sizes_len;
};

bool s2n_custom_send_fn_called = false;
static uint64_t sent_bytes = 0;

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

/* Mock send that will always do a successful full send. */
static int s2n_send_always_passes_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    s2n_custom_send_fn_called = true;
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


int s2n_buffered_send_test_callback_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    s2n_custom_send_fn_called = true;
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    struct s2n_buffered_send_test_callback_params *param = (struct s2n_buffered_send_test_callback_params*) s2n_connection_get_ctx(conn);

    EXPECT_TRUE(param->writes < param->consumed_user_data_sizes_len);
    EXPECT_EQUAL(conn->current_user_data_consumed, param->consumed_user_data_sizes[param->writes]);

    param->writes += 1;

    return len;
}

/* Mock send that will send a set amount of bytes before returning and then setting EAGAIN in subsequent sends. */
static int s2n_buffered_byte_limit_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    ssize_t *bytes_to_send = (ssize_t*) io_context;

    if (s2n_custom_send_fn_called) {
        errno = EAGAIN;
        return -1;
    }

    s2n_custom_send_fn_called = true;

    return *bytes_to_send;
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

    /* s2n_send_should_flush */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        ssize_t mock_total_message_size = S2N_TLS_MAXIMUM_RECORD_LENGTH * 2;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&conn->out, mock_total_message_size));

        uint16_t mock_max_record_size = S2N_TLS_MAXIMUM_RECORD_LENGTH;

        /* Unbuffered send should always return true. */
        EXPECT_TRUE(s2n_send_should_flush(conn, mock_total_message_size));

        /* Buffered send won't flush an empty connection. */
        conn->send_mode = S2N_MULTI_RECORD_SEND;
        conn->custom_send_buffer_size = mock_total_message_size;
        EXPECT_FALSE(s2n_send_should_flush(conn, mock_total_message_size));

        /* If the whole user buffer has been consumed it is time to flush. */
        conn->current_user_data_consumed = mock_total_message_size;
        EXPECT_TRUE(s2n_send_should_flush(conn, mock_total_message_size));
        conn->current_user_data_consumed = 0;

        /* If the space available in the out stuffer is < than mock_max_record_size, it's time to flush. */
        conn->out.write_cursor = (uint32_t)(mock_total_message_size - (mock_max_record_size/2));
        EXPECT_TRUE(s2n_send_should_flush(conn, mock_total_message_size));

        /* If the data available in the out stuffer + the max_write_size is == the send buffer size, we should not flush */
        conn->out.write_cursor = (uint32_t)(mock_total_message_size - mock_max_record_size);
        EXPECT_FALSE(s2n_send_should_flush(conn, mock_total_message_size));

        /* If the space available in the out stuffer is > than mock_max_record_size, we should not flush. */
        conn->out.write_cursor = (uint32_t)(mock_total_message_size - mock_max_record_size*2);
        EXPECT_FALSE(s2n_send_should_flush(conn, mock_total_message_size));
    }

    /* s2n_send partial buffered send */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, SEND_BUFFER_SIZE));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_buffered_send_test_callback_fn));

        uint32_t expected_send_sizes[] = {S2N_DEFAULT_FRAGMENT_LENGTH * 2, SEND_BUFFER_SIZE};
        struct s2n_buffered_send_test_callback_params params = { 0, expected_send_sizes, s2n_array_len(expected_send_sizes)};
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*) &params));

        uint8_t test_data[SEND_BUFFER_SIZE] = {0xA, 0xB, 0xC, 0xD}; /* Rest is 0x0, but we only care about the buffer size */

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_TRUE(params.writes == params.consumed_user_data_sizes_len);
    }

    /* s2n_send full buffered send */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        /* Increase the s2n_send buffer size so the entire test_data buffer fits in a single send. */
        EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, SEND_BUFFER_SIZE * 2));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_buffered_send_test_callback_fn));

        uint32_t expected_send_sizes[] = {SEND_BUFFER_SIZE};
        struct s2n_buffered_send_test_callback_params params = { 0, expected_send_sizes, s2n_array_len(expected_send_sizes)};
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*) &params));

        uint8_t test_data[SEND_BUFFER_SIZE] = {0xA, 0xB, 0xC, 0xD}; /* Rest is 0x0, but we only care about the buffer size */

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_TRUE(params.writes == params.consumed_user_data_sizes_len);
    }

    /* s2n_send unbuffered send */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_buffered_send_test_callback_fn));

        uint32_t expected_send_sizes[] = {S2N_DEFAULT_FRAGMENT_LENGTH, S2N_DEFAULT_FRAGMENT_LENGTH * 2, SEND_BUFFER_SIZE};
        struct s2n_buffered_send_test_callback_params params = { 0, expected_send_sizes, s2n_array_len(expected_send_sizes)};
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*) &params));

        uint8_t test_data[SEND_BUFFER_SIZE] = {0xA, 0xB, 0xC, 0xD}; /* Rest is 0x0, but we only care about the buffer size */

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_TRUE(params.writes == params.consumed_user_data_sizes_len);
    }

    /* s2n_send external s2n_flushes between full buffered sends results in a successful send */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, SEND_BUFFER_SIZE * 2));

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        ssize_t total_bytes_to_send = SEND_BUFFER_SIZE / 3;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_buffered_byte_limit_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*)&total_bytes_to_send));

        uint8_t test_data[SEND_BUFFER_SIZE] = {0xA, 0xB, 0xC, 0xD}; /* Rest is 0x0, but we only care about the buffer size */

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_TRUE(s2n_custom_send_fn_called);

        s2n_custom_send_fn_called = false;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));
        EXPECT_SUCCESS(s2n_flush(conn, &blocked));
        EXPECT_TRUE(s2n_custom_send_fn_called);

        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        /* Everything was already buffered in the stuffer so we shouldn't need to flush again. */
        EXPECT_FALSE(s2n_custom_send_fn_called);
    }

    /* s2n_send external s2n_flushes between partial buffered sends results in a successful send */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, SEND_BUFFER_SIZE));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        ssize_t total_bytes_to_send = SEND_BUFFER_SIZE / 3;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_buffered_byte_limit_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*)&total_bytes_to_send));

        uint8_t test_data[SEND_BUFFER_SIZE] = {0xA, 0xB, 0xC, 0xD}; /* Rest is 0x0, but we only care about the buffer size */

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_TRUE(s2n_custom_send_fn_called);

        s2n_custom_send_fn_called = false;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_send_always_passes_fn));
        EXPECT_SUCCESS(s2n_flush(conn, &blocked));
        EXPECT_TRUE(s2n_custom_send_fn_called);

        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        /* We should flush again because only a partial piece of the test data would have been flushed by the external flush. */
        EXPECT_TRUE(s2n_custom_send_fn_called);
    }

    /* s2n_send buffered sends work if the record sequence number overflows. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, SEND_BUFFER_SIZE));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_buffered_send_test_callback_fn));

        /* The first flush will come from s2n_post_handshake_send calling s2n_flush. We expect two flushes
         * where conn->current_user_data_consumed is the same size as the max record size. */
        uint32_t expected_send_sizes[] = {S2N_DEFAULT_FRAGMENT_LENGTH, S2N_DEFAULT_FRAGMENT_LENGTH, SEND_BUFFER_SIZE};
        struct s2n_buffered_send_test_callback_params params = { 0, expected_send_sizes, s2n_array_len(expected_send_sizes)};
        EXPECT_SUCCESS(s2n_connection_set_ctx(conn, (void*) &params));

        uint8_t test_data[SEND_BUFFER_SIZE] = {0xA, 0xB, 0xC, 0xD}; /* Rest is 0x0, but we only care about the buffer size */

        conn->actual_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        /* The maximum record sequence number of s2n_tls13_aes_256_gcm_sha384 converted to base 256 */
        uint8_t max_record_limit[S2N_TLS_SEQUENCE_NUM_LEN] = {0, 0, 0, 0, 1, 106, 9, 229};
        for (size_t i = 0; i < S2N_TLS_SEQUENCE_NUM_LEN; i++) {
            conn->secure.client_sequence_number[i] = max_record_limit[i];
        }

        /* We will write one record and then hit the encryption limit of s2n_tls13_aes_256_gcm_sha384, triggering a key update. */
        conn->secure.client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN-1] -= 1;

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                SEND_BUFFER_SIZE);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_TRUE(params.writes == params.consumed_user_data_sizes_len);
    }

    END_TEST();
}
