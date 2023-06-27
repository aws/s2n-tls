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
#include <pthread.h>
#include <sys/param.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

/* clang-format off */
#define CLOSED_SEND_RESULT { .result = -1, .error = EPIPE }
#define BLOCK_SEND_RESULT { .result = -1, .error = EAGAIN }
#define PARTIAL_SEND_RESULT(bytes) { .result = bytes, .error = EAGAIN }
#define EXPECTED_SEND_RESULT(bytes) { .result = bytes, .assert_result = true }
#define OK_SEND_RESULT { .result = INT_MAX }
/* clang-format on */

int s2n_check_record_limit(struct s2n_connection *conn, struct s2n_blob *sequence_number);
bool s2n_should_flush(struct s2n_connection *conn, ssize_t total_message_size);

struct s2n_send_result {
    int result;
    int error;
    bool assert_result;
};

struct s2n_send_context {
    size_t calls;
    size_t bytes_sent;
    const struct s2n_send_result *results;
    const size_t results_len;
};

static int s2n_test_send_cb(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_send_context *context = (struct s2n_send_context *) io_context;
    POSIX_ENSURE_REF(context);

    POSIX_ENSURE_LT(context->calls, context->results_len);
    const struct s2n_send_result *result = &context->results[context->calls];

    int retval = MIN((int) len, result->result);
    if (result->assert_result) {
        POSIX_ENSURE_EQ(retval, len);
    }

    context->calls++;
    if (retval > 0) {
        context->bytes_sent += retval;
    }

    errno = result->error;
    return retval;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t test_data[] = "hello world";

    uint8_t large_test_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH + 10] = { 0 };
    struct s2n_blob large_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&large_data_blob, large_test_data, sizeof(large_test_data)));
    EXPECT_OK(s2n_get_public_random_data(&large_data_blob));

    /* Small record sizes will require a LOT of calls to s2n_send.
     * Use this context when they should all succeed.
     */
    struct s2n_send_result results_all_ok[50] = { 0 };
    for (size_t i = 0; i < s2n_array_len(results_all_ok); i++) {
        results_all_ok[i] = (struct s2n_send_result) OK_SEND_RESULT;
    }
    const struct s2n_send_context context_all_ok = {
        .results = results_all_ok,
        .results_len = s2n_array_len(results_all_ok)
    };

    /* Setup a large output buffer that can contain all of large_test_data */
    const size_t buffer_size = 20000;
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_send_buffer_size(config, buffer_size));

    /* Setup an output buffer that is slightly too small for large_test_data */
    const uint32_t smaller_buffer_size = 17300;
    DEFER_CLEANUP(struct s2n_config *smaller_buffer_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(smaller_buffer_config);
    EXPECT_SUCCESS(s2n_config_set_send_buffer_size(smaller_buffer_config, smaller_buffer_size));

    /* Test s2n_should_flush */
    {
        /* Flush if multirecord send not enabled */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);

            /* Multirecord send not enabled */
            EXPECT_FALSE(conn->multirecord_send);
            EXPECT_TRUE(s2n_should_flush(conn, buffer_size));

            /* Multirecord send enabled */
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_TRUE(conn->multirecord_send);
            EXPECT_FALSE(s2n_should_flush(conn, buffer_size));
        };

        /* Flush if all data sent */
        {
            ssize_t send_size = 100;

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* No data sent */
            EXPECT_FALSE(s2n_should_flush(conn, send_size));

            /* Some data sent */
            conn->current_user_data_consumed = send_size / 2;
            EXPECT_FALSE(s2n_should_flush(conn, send_size));

            /* All data sent */
            conn->current_user_data_consumed = send_size;
            EXPECT_TRUE(s2n_should_flush(conn, send_size));
        };

        /* Flush if buffer can't hold max size record */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Uninitialized buffer */
            EXPECT_FALSE(s2n_should_flush(conn, buffer_size));

            /* Empty buffer */
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&conn->out, buffer_size));
            EXPECT_FALSE(s2n_should_flush(conn, buffer_size));

            /* Buffer not empty, but sufficient space remains */
            size_t max_record_size = S2N_TLS_MAX_RECORD_LEN_FOR(conn->max_outgoing_fragment_length);
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&conn->out, buffer_size - max_record_size));
            EXPECT_FALSE(s2n_should_flush(conn, buffer_size));

            /* Insufficient space in buffer */
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&conn->out, 1));
            EXPECT_TRUE(s2n_should_flush(conn, buffer_size));
        };
    };

    /* Total data fits in a single record.
     * Equivalent to not using multirecord.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));

        EXPECT_EQUAL(context.calls, 1);
        EXPECT_EQUAL(context.bytes_sent, conn->wire_bytes_out);
        EXPECT_TRUE(context.bytes_sent > sizeof(test_data));

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, buffer_size);
    };

    /* Send buffer was configured too small for even a single record.
     * Send smaller records.
     *
     * The minimum buffer size we allow generates a fragment size of 5, to prevent
     * fragmenting KeyUpdate messages, which are always 5 bytes. At this minimum size,
     * application data is also fragmented into 5 byte chunks, which is pretty silly,
     * but is an edge case.
     */
    {
        DEFER_CLEANUP(struct s2n_config *min_buffer_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(min_buffer_config);
        EXPECT_SUCCESS(s2n_config_set_send_buffer_size(min_buffer_config, S2N_MIN_SEND_BUFFER_SIZE));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, min_buffer_config));

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        ssize_t send_size = sizeof(test_data);
        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, test_data, send_size, &blocked), send_size);

        /* Since each record only contains two bytes of payload,
         * we need to send a number of records equal to our total send ceil(size / 2).
         */
        uint8_t remainder = (send_size % S2N_MIN_SEND_BUFFER_FRAGMENT_SIZE) ? 1 : 0;
        EXPECT_EQUAL(context.calls, (send_size / S2N_MIN_SEND_BUFFER_FRAGMENT_SIZE) + remainder);
        EXPECT_EQUAL(context.bytes_sent, conn->wire_bytes_out);
        EXPECT_TRUE(context.bytes_sent > send_size);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, S2N_MIN_SEND_BUFFER_SIZE);
    };

    /* Total data fits in multiple records.
     * Without multirecord, this would result in multiple calls to send.
     */
    uint16_t large_test_data_send_size = 0;
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), sizeof(large_test_data));

        EXPECT_EQUAL(context.calls, 1);
        EXPECT_EQUAL(context.bytes_sent, conn->wire_bytes_out);
        EXPECT_TRUE(context.bytes_sent > sizeof(large_test_data));
        large_test_data_send_size = context.bytes_sent;

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, buffer_size);
    };

    /* Total data with multiple records too large for the send buffer.
     * Call send multiple times.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, smaller_buffer_config));

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), sizeof(large_test_data));

        EXPECT_EQUAL(context.calls, 2);
        EXPECT_EQUAL(context.bytes_sent, conn->wire_bytes_out);
        /* Even though it took more send calls,
         * we still sent the same number of records with the same overhead.
         */
        EXPECT_EQUAL(context.bytes_sent, large_test_data_send_size);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, smaller_buffer_size);
    };

    /* Block while buffering multiple records.
     * Send blocks until all buffered data is sent.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        const uint32_t partial_send = 10;
        const uint32_t at_least_one_record = large_test_data_send_size - partial_send - 1;
        const struct s2n_send_result results[] = {
            /* First send writes less than one record before blocking */
            PARTIAL_SEND_RESULT(partial_send), BLOCK_SEND_RESULT,
            /* Second send writes at least one record before blocking */
            PARTIAL_SEND_RESULT(at_least_one_record), BLOCK_SEND_RESULT,
            /* Third send completes */
            OK_SEND_RESULT
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;

        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, partial_send);

        /* Unlike when we buffer a single record at a time, s2n_send does not report each fragment / record flushed.
         * Instead, it won't report any data as sent until all buffered data is flushed.
         */
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, at_least_one_record + partial_send);

        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), sizeof(large_test_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.bytes_sent, large_test_data_send_size);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, buffer_size);
    };

    /* Block while buffering multiple records across multiple send calls.
     * Each send blocks until all buffered data is flushed.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, smaller_buffer_config));

        const uint32_t partial_send = 10;
        const uint32_t at_least_one_flush = smaller_buffer_size - partial_send;
        const struct s2n_send_result results[] = {
            /* First send writes less than one record before blocking */
            PARTIAL_SEND_RESULT(partial_send), BLOCK_SEND_RESULT,
            /* Second send flushes the output buffer before blocking */
            PARTIAL_SEND_RESULT(at_least_one_flush), BLOCK_SEND_RESULT,
            /* Third send completes */
            OK_SEND_RESULT
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;

        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, partial_send);

        /* Write the buffer, which contains two records. */
        ssize_t expected_sent = S2N_DEFAULT_FRAGMENT_LENGTH * 2;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), expected_sent);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

        size_t offset = expected_sent;
        expected_sent = sizeof(large_test_data) - offset;
        EXPECT_EQUAL(s2n_send(conn, large_test_data + offset, sizeof(large_test_data) - offset, &blocked), expected_sent);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.bytes_sent, large_test_data_send_size);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, smaller_buffer_size);
    };

    /* Send a post-handshake message when records are buffered.
     *
     * We only test the KeyUpdate post-handshake message. That can trigger
     * part way through a call to s2n_send if the encryption limit is reached.
     *
     * We can't reliably test NewSessionTicket post-handshake messages.
     * Those could only trigger if an application called s2n_connection_add_new_tickets_to_send
     * part way through a call to s2n_send, which requires calling from another thread
     * at just the right (wrong?) time.
     */
    {
        s2n_blocked_status blocked = 0;

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));

        /* Find size of a KeyUpdate record */
        size_t key_update_size = 0;
        {
            struct s2n_send_context context = context_all_ok;
            EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

            s2n_atomic_flag_set(&conn->key_update_pending);
            EXPECT_SUCCESS(s2n_post_handshake_send(conn, &blocked));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));
            key_update_size = context.bytes_sent;
        };
        EXPECT_TRUE(key_update_size > 0);

        const struct s2n_send_result results[] = {
            /* We expect the buffer to be flushed before the post handshake message */
            OK_SEND_RESULT,
            /* We expect the buffer to be flushed again after the post handshake message */
            EXPECTED_SEND_RESULT(key_update_size),
            OK_SEND_RESULT
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        /* Find record limit */
        uint64_t limit = conn->secure->cipher_suite->record_alg->encryption_limit;
        EXPECT_TRUE(limit > 0);

        /* Initialize sequence number */
        struct s2n_blob seq_num_blob = { 0 };
        struct s2n_stuffer seq_num_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&seq_num_blob, conn->secure->client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
        EXPECT_SUCCESS(s2n_stuffer_init(&seq_num_stuffer, &seq_num_blob));

        /* Set the sequence number so that a KeyUpdate triggers after one more record. */
        uint64_t initial_seq_num = limit - 1;
        EXPECT_SUCCESS(s2n_stuffer_write_uint64(&seq_num_stuffer, initial_seq_num));
        EXPECT_SUCCESS(s2n_check_record_limit(conn, &seq_num_blob));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

        /* Send */
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), sizeof(large_test_data));

        /* Verify KeyUpdate happened: the sequence number was reset */
        uint64_t final_seq_num = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint64(&seq_num_stuffer, &final_seq_num));
        EXPECT_TRUE(final_seq_num < initial_seq_num);

        /* Verify expected send behavior */
        size_t expected_calls = 1 /* first record */ + 1 /* KeyUpdate */ + 1 /* remaining records */;
        EXPECT_EQUAL(context.calls, expected_calls);
        EXPECT_EQUAL(context.bytes_sent, large_test_data_send_size + key_update_size);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, buffer_size);
    };

    /* Test: Alert records are not buffered with ApplicationData records
     *
     * We flush before sending an alert, even if there is sufficient
     * space for the alert record in the send buffer.
     *
     * If this behavior changed, then s2n_should_flush would need to consider
     * the size of a possible alert.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));

        const uint32_t send_size = 10;
        const uint32_t max_app_data_record_size = S2N_TLS_MAX_RECORD_LEN_FOR(send_size);
        const uint32_t max_alert_record_size = S2N_TLS_MAX_RECORD_LEN_FOR(S2N_ALERT_LENGTH);
        const uint32_t min_send_buffer_size = max_app_data_record_size + max_alert_record_size;
        EXPECT_TRUE(min_send_buffer_size <= buffer_size);

        /* Queue the alert */
        EXPECT_OK(s2n_queue_reader_no_renegotiation_alert(conn));

        /* Send the Application Data and Alert */
        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, send_size, &blocked), send_size);

        /* We expect two separate send calls: one for the application data record
         * and one for the alert record.
         */
        EXPECT_EQUAL(context.calls, 2);

        /* We expect that the output buffer never contained all data sent,
         * since that data was split between two records.
         */
        EXPECT_TRUE(conn->out.high_water_mark < context.bytes_sent);
    };

    /* Send a post-handshake message when records are buffered, and IO blocks */
    {
        s2n_blocked_status blocked = 0;

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));

        /* Find size of a KeyUpdate record */
        size_t key_update_size = 0;
        {
            struct s2n_send_context context = context_all_ok;
            EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

            s2n_atomic_flag_set(&conn->key_update_pending);
            EXPECT_SUCCESS(s2n_post_handshake_send(conn, &blocked));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));
            key_update_size = context.bytes_sent;
        }
        EXPECT_TRUE(key_update_size > 0);

        /* Block the first two calls to send, only allowing the third to succeed. */
        const struct s2n_send_result results[] = {
            /* Initial ApplicationData records */
            BLOCK_SEND_RESULT,
            BLOCK_SEND_RESULT,
            OK_SEND_RESULT,
            /* KeyUpdate record */
            BLOCK_SEND_RESULT,
            BLOCK_SEND_RESULT,
            EXPECTED_SEND_RESULT(key_update_size),
            /* Remaining ApplicationData records */
            BLOCK_SEND_RESULT,
            BLOCK_SEND_RESULT,
            OK_SEND_RESULT,
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        /* Find record limit */
        uint64_t limit = conn->secure->cipher_suite->record_alg->encryption_limit;
        EXPECT_TRUE(limit > 0);

        /* Initialize sequence number */
        struct s2n_blob seq_num_blob = { 0 };
        struct s2n_stuffer seq_num_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&seq_num_blob, conn->secure->client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
        EXPECT_SUCCESS(s2n_stuffer_init(&seq_num_stuffer, &seq_num_blob));

        /* Set the sequence number so that a KeyUpdate triggers after one more record. */
        uint64_t initial_seq_num = limit - 1;
        EXPECT_SUCCESS(s2n_stuffer_write_uint64(&seq_num_stuffer, initial_seq_num));
        EXPECT_SUCCESS(s2n_check_record_limit(conn, &seq_num_blob));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

        /* Send until all data written */
        size_t total = 0;
        while (total < sizeof(large_test_data)) {
            ssize_t sent = s2n_send(conn, large_test_data + total, sizeof(large_test_data) - total, &blocked);
            if (sent >= S2N_SUCCESS) {
                total += sent;
            } else {
                EXPECT_EQUAL(s2n_errno, S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            }
        }

        /* Verify KeyUpdate happened: the sequence number was reset */
        uint64_t final_seq_num = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint64(&seq_num_stuffer, &final_seq_num));
        EXPECT_TRUE(final_seq_num < initial_seq_num);

        /* Verify expected send behavior */
        size_t expected_calls = s2n_array_len(results);
        EXPECT_EQUAL(context.calls, expected_calls);
        EXPECT_EQUAL(context.bytes_sent, large_test_data_send_size + key_update_size);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, buffer_size);
    };

    END_TEST();
}
