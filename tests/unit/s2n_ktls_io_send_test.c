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

#include "s2n.h"
#include "s2n_test.h"
#include "stdio.h"
#include "testlib/s2n_ktls_test_utils.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_random.h"

#define S2N_TEST_TO_SEND    10
#define S2N_TEST_MSG_IOVLEN 4

struct s2n_test_ktls_io_send_then_fail_ctx {
    size_t send_count;
    struct s2n_test_ktls_io_fail_ctx *fail_ctx;
};

static ssize_t s2n_test_ktls_sendmsg_send_then_fail(void *io_context, const struct msghdr *msg)
{
    struct s2n_test_ktls_io_send_then_fail_ctx *io_ctx = (struct s2n_test_ktls_io_send_then_fail_ctx *) io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->fail_ctx->invoked_count++;

    if (io_ctx->send_count) {
        io_ctx->send_count--;
        /* return 1 to simulate 1 byte of data was written */
        return 1;
    }
    errno = io_ctx->fail_ctx->errno_code;
    return -1;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t test_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test s2n_ktls_send */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            struct iovec msg_iov_valid = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;

            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send(NULL, &msg_iov_valid, 1, 0, &blocked), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send(server, NULL, 1, 0, &blocked), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send(server, &msg_iov_valid, 1, 0, NULL), S2N_ERR_NULL);
        };

        /* Attempt send with msg_iovlen = 1, offset = 0 */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = s2n_ktls_send(server, &msg_iov, 1, 0, &blocked);
            EXPECT_SUCCESS(bytes_written);
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_data(&client_in, test_data, S2N_TEST_TO_SEND));

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 1);
        };

        /* Attempt send with msg_iovlen > 1, offset = 0 */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

            struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
            size_t total_sent = 0;
            for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                msg_iov[i].iov_base = test_data + total_sent;
                msg_iov[i].iov_len = S2N_TEST_TO_SEND;
                total_sent += S2N_TEST_TO_SEND;
            }

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, 0, &blocked);
            EXPECT_SUCCESS(bytes_written);
            EXPECT_EQUAL(bytes_written, total_sent);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, total_sent));
            EXPECT_OK(s2n_test_validate_data(&client_in, test_data, total_sent));

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 1);
        };

        /* Simulate blocked error when 0 bytes were sent */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));
            /* disable growable to simulate blocked/network buffer full */
            client_in.data_buffer.growable = false;

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t blocked_invoked_count = 5;
            for (size_t i = 0; i < blocked_invoked_count; i++) {
                EXPECT_FAILURE_WITH_ERRNO(
                        s2n_ktls_send(server, &msg_iov, 1, 0, &blocked),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            }

            /* enable growable to unblock write */
            /* cppcheck-suppress redundantAssignment */
            client_in.data_buffer.growable = true;
            size_t bytes_written = s2n_ktls_send(server, &msg_iov, 1, 0, &blocked);
            EXPECT_SUCCESS(bytes_written);
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_data(&client_in, test_data, S2N_TEST_TO_SEND));

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, blocked_invoked_count + 1);
        };

        /* Simulate blocked error when > 0 bytes were sent */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

            /* disable growable to simulate blocked/network buffer full but alloc
             * enough space to write 1 fragment worth of bytes */
            s2n_stuffer_alloc(&client_in.data_buffer, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE);
            client_in.data_buffer.growable = false;
            /* send just over max fragment size so that there are 2 sendmsg syscall and
             * the second syscall blocks. */
            size_t expected_send = S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE;
            size_t to_send = expected_send + 1;

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = to_send };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = s2n_ktls_send(server, &msg_iov, 1, 0, &blocked);
            EXPECT_SUCCESS(bytes_written);
            EXPECT_EQUAL(bytes_written, expected_send);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, expected_send));
            EXPECT_OK(s2n_test_validate_data(&client_in, test_data, expected_send));

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 2);
        };

        /* Simulate non-blocked error when 0 bytes were sent */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            struct s2n_test_ktls_io_fail_ctx io_ctx = {
                .errno_code = EINVAL,
            };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_fail, &io_ctx));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send(server, &msg_iov, 1, 0, &blocked), S2N_ERR_IO);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

            EXPECT_EQUAL(io_ctx.invoked_count, 1);
        };

        /* Simulate non-blocked error when > 0 bytes were sent */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);

            size_t send_count = 2;
            struct s2n_test_ktls_io_fail_ctx fail_io_ctx = {
                .errno_code = EINVAL,
            };
            struct s2n_test_ktls_io_send_then_fail_ctx io_ctx = {
                .send_count = send_count,
                .fail_ctx = &fail_io_ctx,
            };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_send_then_fail, &io_ctx));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            /* expect error rather than bytes_written, unlike S2N_ERR_IO_BLOCKED */
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send(server, &msg_iov, 1, 0, &blocked), S2N_ERR_IO);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

            EXPECT_EQUAL(fail_io_ctx.invoked_count, send_count + 1);
        };

        /* Attempt to send 0 bytes */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

            size_t send_0_bytes = 0;
            struct iovec msg_iov = { .iov_base = NULL, .iov_len = send_0_bytes };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            size_t bytes_written = s2n_ktls_send(server, &msg_iov, 1, 0, &blocked);
            EXPECT_SUCCESS(bytes_written);
            EXPECT_EQUAL(bytes_written, send_0_bytes);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 0);
        };

        /* Test offset writes. */
        {
            /* Attempt send with msg_iovlen = 1, offset > 0
             *
             * Test when we offset the first iovec for msg_iovlen == 1
             *         v
             * [ { 1 2 3 4 5 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
                s2n_blocked_status blocked = S2N_NOT_BLOCKED;

                size_t offset = 3;
                size_t total_sent = S2N_TEST_TO_SEND - offset;
                size_t bytes_written = s2n_ktls_send(server, &msg_iov, 1, offset, &blocked);
                EXPECT_SUCCESS(bytes_written);
                EXPECT_EQUAL(bytes_written, total_sent);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                /* confirm sent data */
                EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, total_sent));
                EXPECT_OK(s2n_test_validate_data(&client_in, test_data + offset, total_sent));

                EXPECT_EQUAL(client_in.sendmsg_invoked_count, 1);
            };

            /* Attempt send with `msg_iovlen > 1` and `0 < offset < iov_len`
             *
             * Test when we offset partially into the first iovec and msg_iovlen > 1
             *         v
             * [ { 1 2 3 4 5 } { 1 2 3 } { 1 2 3 4 5 6 7 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                size_t total_sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    msg_iov[i].iov_base = test_data + total_sent;
                    msg_iov[i].iov_len = S2N_TEST_TO_SEND;
                    total_sent += S2N_TEST_TO_SEND;
                }

                size_t offset = 4;
                EXPECT_TRUE(0 < offset && offset < S2N_TEST_TO_SEND);
                total_sent -= offset;

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                size_t bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, offset, &blocked);
                EXPECT_SUCCESS(bytes_written);
                EXPECT_EQUAL(bytes_written, total_sent);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                /* confirm sent data */
                EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, total_sent));
                EXPECT_OK(s2n_test_validate_data(&client_in, test_data + offset, total_sent));

                EXPECT_EQUAL(client_in.sendmsg_invoked_count, 1);
            };

            /* Attempt send with `msg_iovlen > 1` and `0 < iov_len < offset`
             *
             * Test when we offset the first and partially into the second iovec and msg_iovlen > 1
             *                     v
             * [ { 1 2 3 4 5 } { 1 2 3 } { 1 2 3 4 5 6 7 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                size_t total_sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    msg_iov[i].iov_base = test_data + total_sent;
                    msg_iov[i].iov_len = S2N_TEST_TO_SEND;
                    total_sent += S2N_TEST_TO_SEND;
                }

                size_t offset = S2N_TEST_TO_SEND + 4;
                EXPECT_TRUE(0 < offset && S2N_TEST_TO_SEND < offset);
                total_sent -= offset;

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                size_t bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, offset, &blocked);
                EXPECT_SUCCESS(bytes_written);
                EXPECT_EQUAL(bytes_written, total_sent);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                /* confirm sent data */
                EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, total_sent));
                EXPECT_OK(s2n_test_validate_data(&client_in, test_data + offset, total_sent));

                EXPECT_EQUAL(client_in.sendmsg_invoked_count, 1);
            };
        };

        /* Test partial writes due to fragmentation. */
        {
            /* Partial write sends full iovec: iov_len_to_send == S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE
             *
             * `W` indicates written:
             * [ { 1 2 3 } { 1 2 3 4 } { 1 2 3 } ] -> [ { W W W } { 1 2 3 4 } { 1 2 3 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                /* sent S2N_TEST_MSG_IOVLEN records of size S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE each */
                size_t iov_len_to_send = S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE;
                size_t expected_invocations = S2N_TEST_MSG_IOVLEN;

                struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                size_t total_sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    msg_iov[i].iov_base = test_data + total_sent;
                    msg_iov[i].iov_len = iov_len_to_send;
                    total_sent += iov_len_to_send;
                }

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                size_t bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, 0, &blocked);
                EXPECT_SUCCESS(bytes_written);
                EXPECT_EQUAL(bytes_written, total_sent);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                /* validate ancillary header */
                for (size_t i = 0; i < expected_invocations; i++) {
                    EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE));
                    /* consume the header in order to then validate the next header */
                    EXPECT_NOT_NULL(s2n_stuffer_raw_read(&client_in.ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));
                }
                EXPECT_OK(s2n_test_validate_data(&client_in, test_data, total_sent));

                EXPECT_EQUAL(client_in.sendmsg_invoked_count, expected_invocations);
            };

            /* Partial write sends one partial iovec: iov_len_to_send > S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE
             *
             * `W` indicates written:
             * [ { 1 2 3 } { 1 2 3 4 } { 1 2 3 } ] -> [ { W W 3 } { 1 2 3 4 } { 1 2 3 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                /* sent S2N_TEST_MSG_IOVLEN * 2 records of size S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE each */
                size_t iov_len_to_send = S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE * 2;
                size_t expected_invocations = S2N_TEST_MSG_IOVLEN * 2;

                struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                size_t total_sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    msg_iov[i].iov_base = test_data + total_sent;
                    msg_iov[i].iov_len = iov_len_to_send;
                    total_sent += iov_len_to_send;
                }

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                size_t bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, 0, &blocked);
                EXPECT_SUCCESS(bytes_written);
                /* only max_fragment_len amount sent */
                EXPECT_EQUAL(bytes_written, total_sent);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                /* validate ancillary header */
                for (size_t i = 0; i < expected_invocations; i++) {
                    EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE));
                    /* consume the header in order to then validate the next header */
                    EXPECT_NOT_NULL(s2n_stuffer_raw_read(&client_in.ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));
                }
                EXPECT_OK(s2n_test_validate_data(&client_in, test_data, total_sent));

                EXPECT_EQUAL(client_in.sendmsg_invoked_count, expected_invocations);
            };

            /* Partial write sends one full iovec and one partial iovec: iov_len_to_send < S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE
             *
             * `W` indicates written:
             * [ { 1 2 3 } { 1 2 3 4 } { 1 2 3 } ] -> [ { W W W } { W W 3 4 } { 1 2 3 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                /* sent S2N_TEST_MSG_IOVLEN / 2 records of size S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE each */
                size_t iov_len_to_send = S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE / 2;
                size_t expected_invocations = S2N_TEST_MSG_IOVLEN / 2;

                struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                size_t total_sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    msg_iov[i].iov_base = test_data + total_sent;
                    msg_iov[i].iov_len = iov_len_to_send;
                    total_sent += iov_len_to_send;
                }

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                size_t bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, 0, &blocked);
                EXPECT_SUCCESS(bytes_written);
                /* only max_fragment_len amount sent */
                EXPECT_EQUAL(bytes_written, total_sent);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                /* validate ancillary header */
                for (size_t i = 0; i < expected_invocations; i++) {
                    EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE));
                    /* consume the header in order to then validate the next header */
                    EXPECT_NOT_NULL(s2n_stuffer_raw_read(&client_in.ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));
                }
                EXPECT_OK(s2n_test_validate_data(&client_in, test_data, total_sent));

                EXPECT_EQUAL(client_in.sendmsg_invoked_count, expected_invocations);
            };

            /* Fuzz partial writes amount */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                for (size_t iov_len_to_send = 1; iov_len_to_send < S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE * 50; iov_len_to_send += 10) {
                    struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                    size_t total_sent = 0;
                    for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                        msg_iov[i].iov_base = test_data + total_sent;
                        msg_iov[i].iov_len = iov_len_to_send;
                        total_sent += iov_len_to_send;
                    }

                    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                    size_t bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, 0, &blocked);
                    EXPECT_SUCCESS(bytes_written);
                    EXPECT_EQUAL(bytes_written, total_sent);
                    EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                    size_t first_record_size = MIN(total_sent, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE);
                    EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, first_record_size));
                    EXPECT_OK(s2n_test_validate_data(&client_in, test_data, total_sent));

                    /* reset buffers for the next iteration */
                    s2n_stuffer_wipe(&client_in.ancillary_buffer);
                    s2n_stuffer_wipe(&client_in.data_buffer);

                    EXPECT_TRUE(client_in.sendmsg_invoked_count > 0);
                }
            };
        };

        /* Test partial writes due to blocked error. s2n_ktls_send is called multiple times. */
        {
            /* Partial write sends full iovec: iov_len == S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE
             *
             * `W` indicates written:
             * [ { 1 2 3 } { 1 2 3 4 } { 1 2 3 } ] -> [ { W W W } { 1 2 3 4 } { 1 2 3 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                size_t total_sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    msg_iov[i].iov_base = test_data + total_sent;
                    /* In the following test we set each iov_len to the max fragment size so
                     * that each iovec is sent in a separate record. */
                    msg_iov[i].iov_len = S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE;
                    total_sent += S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE;
                }

                /* disable growable to simulate blocked/network buffer full but alloc
                 * enough space to write 1 fragment worth of bytes */
                s2n_stuffer_alloc(&client_in.data_buffer, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE);
                client_in.data_buffer.growable = false;

                size_t sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                    size_t bytes_written = 0;
                    bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, sent, &blocked);
                    EXPECT_SUCCESS(bytes_written);
                    EXPECT_EQUAL(bytes_written, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE);
                    sent += bytes_written;
                    /* should return block until all data has been sent */
                    if (sent < total_sent) {
                        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                    } else {
                        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                    }

                    /* confirm sent data */
                    EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE));
                    EXPECT_OK(s2n_test_validate_data(&client_in, test_data, sent));

                    /* resize */
                    client_in.data_buffer.growable = true;
                    EXPECT_SUCCESS(s2n_stuffer_resize(&client_in.data_buffer, sent + S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE));
                    client_in.data_buffer.growable = false;
                }

                /* Since each iov_len is of size S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE, all except the last
                 * call attempts to send again and blocks. */
                EXPECT_EQUAL(client_in.sendmsg_invoked_count, (S2N_TEST_MSG_IOVLEN * 2) - 1);
            };

            /* Partial write sends one partial iovec: iov_len > S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE
             *
             * `W` indicates written:
             * [ { 1 2 3 } { 1 2 3 4 } { 1 2 3 } ] -> [ { W W 3 } { 1 2 3 4 } { 1 2 3 } ]
             */
            {};

            /* Partial write sends one full iovec and one partial iovec: iov_len < S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE
             *
             * `W` indicates written:
             * [ { 1 2 3 } { 1 2 3 4 } { 1 2 3 } ] -> [ { W W W } { W W 3 4 } { 1 2 3 } ]
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

                /* sent S2N_TEST_MSG_IOVLEN / 2 records of size S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE each */
                size_t iov_len_to_send = S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE / 2;
                size_t expected_invocations = S2N_TEST_MSG_IOVLEN / 2;

                struct iovec msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
                size_t total_sent = 0;
                for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                    msg_iov[i].iov_base = test_data + total_sent;
                    /* In the following test we set each iov_len to the max fragment size so
                     * that each iovec is sent in a separate record. */
                    msg_iov[i].iov_len = iov_len_to_send;
                    total_sent += iov_len_to_send;
                }

                /* disable growable to simulate blocked/network buffer full but alloc
                 * enough space to write 1 fragment worth of bytes */
                s2n_stuffer_alloc(&client_in.data_buffer, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE);
                client_in.data_buffer.growable = false;

                size_t sent = 0;
                for (size_t i = 0; i < expected_invocations; i++) {
                    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                    size_t bytes_written = 0;
                    bytes_written = s2n_ktls_send(server, msg_iov, S2N_TEST_MSG_IOVLEN, sent, &blocked);
                    EXPECT_SUCCESS(bytes_written);
                    printf("\n%zu", bytes_written);
                    EXPECT_EQUAL(bytes_written, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE);
                    sent += bytes_written;
                    /* should return block until all data has been sent */
                    if (sent < total_sent) {
                        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                    } else {
                        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                    }

                    /* confirm sent data */
                    EXPECT_OK(s2n_test_validate_ancillary(&client_in, TLS_APPLICATION_DATA, S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE));
                    EXPECT_OK(s2n_test_validate_data(&client_in, test_data, sent));

                    /* resize */
                    client_in.data_buffer.growable = true;
                    EXPECT_SUCCESS(s2n_stuffer_resize(&client_in.data_buffer, sent + S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE));
                    client_in.data_buffer.growable = false;
                }

                /* Since each iov_len is of size S2N_TEST_KTLS_MOCK_MAX_FRAG_SIZE, all except the last
                 * call attempts to send again and blocks. */
                EXPECT_EQUAL(client_in.sendmsg_invoked_count, S2N_TEST_MSG_IOVLEN - 1);
            };

            /* Fuzz partial writes amount */
            {};
        };
    };

    END_TEST();
}
