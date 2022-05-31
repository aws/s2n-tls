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


int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_send cannot be called concurrently */
    {
        /* Setup connections */
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
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

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* s2n_send tracks conn->wire_bytes_out on send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
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

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* s2n_send tracks conn->wire_bytes_out on partial send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
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

    END_TEST();
}
