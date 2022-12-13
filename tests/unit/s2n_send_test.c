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
#include <sys/param.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

/* clang-format off */
#define CLOSED_SEND_RESULT { .result = -1, .error = EPIPE }
#define BLOCK_SEND_RESULT { .result = -1, .error = EAGAIN }
#define PARTIAL_SEND_RESULT(bytes) { .result = bytes, .error = EAGAIN }
#define OK_SEND_RESULT { .result = INT_MAX }
/* clang-format on */

enum s2n_test_mfl {
    S2N_MFL_DEFAULT = 0,
    S2N_MFL_LARGE,
    S2N_MFL_SMALL,
    S2N_MFL_MINIMUM,
    S2N_MFL_COUNT,
};

static S2N_RESULT s2n_set_test_max_fragment_len(struct s2n_connection *conn, enum s2n_test_mfl mfl)
{
    switch (mfl) {
        case S2N_MFL_DEFAULT:
            break;
        case S2N_MFL_LARGE:
            EXPECT_SUCCESS(s2n_connection_prefer_throughput(conn));
            break;
        case S2N_MFL_SMALL:
            EXPECT_SUCCESS(s2n_connection_prefer_low_latency(conn));
            break;
        case S2N_MFL_MINIMUM:
            conn->max_outgoing_fragment_length = mfl_code_to_length[1];
            break;
        case S2N_MFL_COUNT:
            RESULT_BAIL(S2N_ERR_INVALID_ARGUMENT);
            break;
    }
    return S2N_RESULT_OK;
}

struct s2n_send_result {
    int result;
    int error;
};

struct s2n_send_context {
    size_t calls;
    size_t bytes_sent;
    const struct s2n_send_result *results;
    const size_t results_len;
};

bool s2n_custom_send_fn_called = false;
int s2n_expect_concurrent_error_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection *) io_context;
    s2n_custom_send_fn_called = true;

    s2n_blocked_status blocked = 0;
    ssize_t result = s2n_send(conn, buf, len, &blocked);
    EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_REENTRANCY);
    return result;
}

static int s2n_test_send_cb(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_send_context *context = (struct s2n_send_context *) io_context;
    POSIX_ENSURE_REF(context);

    POSIX_ENSURE_LT(context->calls, context->results_len);
    const struct s2n_send_result *result = &context->results[context->calls];

    int retval = MIN((int) len, result->result);

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

    /* Calculating the record size for given data can be tricky.
     * Instead, let's set the values based on the results of tests.
     */
    ssize_t test_data_bytes_sent = 0;

    /* s2n_send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));

        EXPECT_EQUAL(context.calls, 1);
        EXPECT_EQUAL(context.bytes_sent, conn->wire_bytes_out);

        /* Set the expected record size for future tests */
        test_data_bytes_sent = context.bytes_sent;
        EXPECT_TRUE(test_data_bytes_sent > sizeof(test_data));
    };

    /* Calculating the max record size for a given max fragment length can be tricky.
     * Instead, let's set the values based on the results of tests.
     */
    ssize_t max_frag_bytes_sent[S2N_MFL_COUNT] = { 0 };

    /* Track the size of the output buffer.
     * It should be constant across all tests with the same max fragment length.
     */
    uint32_t out_size[S2N_MFL_COUNT] = { 0 };

    /* Send exactly the maximum fragment size */
    for (size_t mfl = 0; mfl < S2N_MFL_COUNT; mfl++) {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_OK(s2n_set_test_max_fragment_len(conn, mfl));
        uint32_t fragment_len = conn->max_outgoing_fragment_length;

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;

        /* Send exactly the fragment length */
        EXPECT_EQUAL(s2n_send(conn, large_test_data, fragment_len, &blocked), fragment_len);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.calls, 1);

        /* Set the expected record size for future tests */
        max_frag_bytes_sent[mfl] = context.bytes_sent;
        EXPECT_TRUE(max_frag_bytes_sent[mfl] > 0);

        /* Set the expected output buffer size for future tests */
        out_size[mfl] = conn->out.blob.size;
        EXPECT_TRUE(out_size[mfl] > 0);

        /* Sanity check: Send one byte more than the fragment length.
         * If this is actually the maximum fragment length, one extra byte will
         * lead to an extra record / extra call to send.
         */
        context.calls = 0;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, fragment_len + 1, &blocked), fragment_len + 1);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.calls, 2);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[mfl]);
    }

    /* s2n_send cannot be called concurrently */
    {
        /* Setup connections */
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Setup bad send callback */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_expect_concurrent_error_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        s2n_blocked_status blocked = 0;
        s2n_custom_send_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_send_fn_called);
        EXPECT_EQUAL(0, conn->wire_bytes_out);
    };

    /* s2n_send tracks conn->wire_bytes_out on send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_EQUAL(0, conn->wire_bytes_out);

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));

        EXPECT_EQUAL(context.calls, 1);
        EXPECT_EQUAL(context.bytes_sent, test_data_bytes_sent);
        EXPECT_EQUAL(context.bytes_sent, conn->wire_bytes_out);
        EXPECT_EQUAL(context.bytes_sent, s2n_connection_get_wire_bytes_out(conn));
    };

    /* s2n_send tracks conn->wire_bytes_out on partial send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_EQUAL(0, conn->wire_bytes_out);

        const uint32_t partial_send = 10;
        const struct s2n_send_result results[] = {
            PARTIAL_SEND_RESULT(partial_send),
            CLOSED_SEND_RESULT,
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked), S2N_ERR_IO);

        EXPECT_EQUAL(context.calls, 2);
        EXPECT_EQUAL(context.bytes_sent, partial_send);
        EXPECT_EQUAL(context.bytes_sent, conn->wire_bytes_out);
        EXPECT_EQUAL(context.bytes_sent, s2n_connection_get_wire_bytes_out(conn));
    };

    /* s2n_send sends all data, despite partial writes */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        const struct s2n_send_result results[] = {
            PARTIAL_SEND_RESULT(1),
            PARTIAL_SEND_RESULT(5),
            PARTIAL_SEND_RESULT(2),
            OK_SEND_RESULT,
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.calls, s2n_array_len(results));
        EXPECT_EQUAL(context.bytes_sent, test_data_bytes_sent);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);
    };

    /* s2n_send would block and must be retried */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        const uint32_t partial_send = 10;
        const struct s2n_send_result results[] = {
            PARTIAL_SEND_RESULT(partial_send),
            BLOCK_SEND_RESULT,
            PARTIAL_SEND_RESULT(partial_send),
            BLOCK_SEND_RESULT,
            OK_SEND_RESULT
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;

        /* First attempt blocks */
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, partial_send);

        /* Second attempt blocks */
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, test_data, sizeof(test_data), &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, partial_send * 2);

        /* Third attempt completes */
        EXPECT_EQUAL(s2n_send(conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.bytes_sent, test_data_bytes_sent);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);
    };

    /* Calculating the record size for given data can be tricky.
     * Instead, let's set the values based on the results of tests.
     */
    ssize_t large_test_data_bytes_sent = 0;

    /* s2n_send sends multiple records worth of data */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        struct s2n_send_result results[] = { OK_SEND_RESULT, OK_SEND_RESULT, OK_SEND_RESULT };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), sizeof(large_test_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.calls, s2n_array_len(results));

        large_test_data_bytes_sent = context.bytes_sent;
        EXPECT_TRUE(large_test_data_bytes_sent > sizeof(large_test_data));

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);
    };

    /* s2n_send sends all records and data, despite partial writes */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        struct s2n_send_result results[] = {
            PARTIAL_SEND_RESULT(10), OK_SEND_RESULT,
            OK_SEND_RESULT,
            PARTIAL_SEND_RESULT(5), PARTIAL_SEND_RESULT(1), OK_SEND_RESULT
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), sizeof(large_test_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.calls, s2n_array_len(results));
        EXPECT_EQUAL(context.bytes_sent, large_test_data_bytes_sent);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);
    };

    /* s2n_send would block while sending multiple records */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        const uint32_t partial_send = 10;
        struct s2n_send_result results[] = {
            OK_SEND_RESULT,
            PARTIAL_SEND_RESULT(partial_send),
            BLOCK_SEND_RESULT,
            PARTIAL_SEND_RESULT(partial_send),
            BLOCK_SEND_RESULT,
            OK_SEND_RESULT, OK_SEND_RESULT, OK_SEND_RESULT
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        ssize_t record_size = max_frag_bytes_sent[S2N_MFL_DEFAULT];

        /* First attempt blocks after writing one record */
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked),
                S2N_DEFAULT_FRAGMENT_LENGTH);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, record_size + partial_send);

        /* Don't re-send the data already sent. */
        const uint32_t offset = S2N_DEFAULT_FRAGMENT_LENGTH;

        /* Second attempt blocks without writing another record */
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, large_test_data + offset, sizeof(large_test_data) - offset, &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, record_size + partial_send + partial_send);

        /* Third attempt completes */
        EXPECT_EQUAL(s2n_send(conn, large_test_data + offset, sizeof(large_test_data) - offset, &blocked),
                sizeof(large_test_data) - S2N_DEFAULT_FRAGMENT_LENGTH);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.bytes_sent, large_test_data_bytes_sent);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);
    };

    /* s2n_send would block after sending multiple records.
     * ALL flushed records must be reported to the caller.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        struct s2n_send_result results[] = {
            OK_SEND_RESULT,
            OK_SEND_RESULT,
            BLOCK_SEND_RESULT,
            OK_SEND_RESULT,
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        ssize_t record_size = max_frag_bytes_sent[S2N_MFL_DEFAULT];

        /* First attempt blocks after writing two records */
        ssize_t expected_send = S2N_DEFAULT_FRAGMENT_LENGTH * 2;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), expected_send);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        EXPECT_EQUAL(context.bytes_sent, record_size * 2);

        /* Don't re-send the data already sent. */
        const uint32_t offset = expected_send;

        /* Second attempt completes */
        EXPECT_EQUAL(s2n_send(conn, large_test_data + offset, sizeof(large_test_data) - offset, &blocked),
                sizeof(large_test_data) - offset);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(context.bytes_sent, large_test_data_bytes_sent);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);
    };

    /* Sending multiple records supports different maximum fragment lengths */
    for (size_t mfl = 0; mfl < S2N_MFL_COUNT; mfl++) {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));
        EXPECT_OK(s2n_set_test_max_fragment_len(conn, mfl));

        struct s2n_send_context context = context_all_ok;
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));

        s2n_blocked_status blocked = 0;
        EXPECT_EQUAL(s2n_send(conn, large_test_data, sizeof(large_test_data), &blocked), sizeof(large_test_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        /* We expect enough calls to send to split the payload into records */
        size_t expected_calls = ceil(sizeof(large_test_data) / (double) conn->max_outgoing_fragment_length);
        EXPECT_EQUAL(context.calls, expected_calls);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[mfl]);
    }

    /* Test dynamic record threshold record fragmentation */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Retrieve the fragment size to expect */
        uint16_t single_mtu_mfl = 0;
        EXPECT_OK(s2n_record_min_write_payload_size(conn, &single_mtu_mfl));

        /* Set the dynamic record threshold large enough for two small records */
        const uint32_t resize_threshold = single_mtu_mfl * 2;
        EXPECT_SUCCESS(s2n_connection_set_dynamic_record_threshold(conn, resize_threshold, UINT16_MAX));

        struct s2n_send_result results[] = {
            /* Block before sending the first record so that we can examine
             * the connection state after buffering the first record.
             */
            BLOCK_SEND_RESULT, OK_SEND_RESULT,
            /* Send the second record */
            BLOCK_SEND_RESULT, OK_SEND_RESULT,
            /* Send the third record */
            OK_SEND_RESULT,
            BLOCK_SEND_RESULT
        };
        struct s2n_send_context context = { .results = results, .results_len = s2n_array_len(results) };
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) &context));
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_test_send_cb));

        s2n_blocked_status blocked = 0;
        const size_t send_size = single_mtu_mfl * 2;

        /* The first call to s2n_send blocks before sending the first record. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(conn, large_test_data, send_size, &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        /* No records have been sent yet. */
        EXPECT_EQUAL(context.bytes_sent, 0);
        /* The first record is buffered,
         * so its bytes still count towards the resize_threshold.
         * We have NOT passed the threshold.
         */
        EXPECT_EQUAL(conn->active_application_bytes_consumed, single_mtu_mfl);
        EXPECT_TRUE(conn->active_application_bytes_consumed < resize_threshold);
        /* Output buffer should be able to handle the default size, not the single MTU size.
         * Otherwise, the output buffer would need to resize later.
         */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);

        /* The second call to s2n_send flushes the buffered first record,
         * but blocks before sending the second record.
         */
        ssize_t result = s2n_send(conn, large_test_data, send_size, &blocked);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        /* First small, single-MTU record was sent. */
        EXPECT_EQUAL(result, single_mtu_mfl);
        EXPECT_TRUE(context.bytes_sent < ETH_MTU);
        /* The second record is buffered,
         * so its bytes count towards the resize_threshold.
         * We have therefore hit the threshold.
         */
        EXPECT_EQUAL(conn->active_application_bytes_consumed, resize_threshold);
        /* Output buffer should be able to handle the default size, not the single MTU size.
         * Otherwise, the output buffer would need to resize later.
         */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);

        /* The third call to s2n_send flushes the second record. */
        result = s2n_send(conn, large_test_data, send_size - single_mtu_mfl, &blocked);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        /* Second small, single-MTU record was sent. */
        EXPECT_EQUAL(result, single_mtu_mfl);
        /* There should be no change regarding the resize_threshold,
         * since we did not construct any new records.
         */
        EXPECT_EQUAL(conn->active_application_bytes_consumed, resize_threshold);
        /* Output buffer should be able to handle the default size, not the single MTU size.
         * Otherwise, the output buffer would need to resize later.
         */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);

        /* The fourth call to s2n_send sends the third record. */
        result = s2n_send(conn, large_test_data, conn->max_outgoing_fragment_length * 2, &blocked);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        /* We have passed the resize_threshold, so records are no longer small.
         * Instead they use the standard connection fragment length.
         */
        EXPECT_TRUE(result > single_mtu_mfl);
        EXPECT_EQUAL(result, conn->max_outgoing_fragment_length);

        /* Verify output buffer */
        EXPECT_EQUAL(conn->out.blob.size, out_size[S2N_MFL_DEFAULT]);
    };

    END_TEST();
}
