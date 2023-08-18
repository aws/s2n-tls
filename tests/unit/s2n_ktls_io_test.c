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
#include "testlib/s2n_ktls_test_utils.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_random.h"

#define S2N_TEST_TO_SEND    10
#define S2N_TEST_MSG_IOVLEN 5

S2N_RESULT s2n_ktls_set_control_data(struct msghdr *msg, char *buf, size_t buf_size,
        int cmsg_type, uint8_t record_type);
S2N_RESULT s2n_ktls_get_control_data(struct msghdr *msg, int cmsg_type, uint8_t *record_type);

/* Mock implementation used for validating failure behavior */
struct s2n_test_ktls_io_fail {
    size_t invoked_count;
    size_t errno_code;
};

static ssize_t s2n_test_ktls_sendmsg_fail(void *io_context, const struct msghdr *msg)
{
    struct s2n_test_ktls_io_fail *io_ctx = (struct s2n_test_ktls_io_fail *) io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->invoked_count++;
    errno = io_ctx->errno_code;
    return -1;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t test_record_type = 43;
    /* test data */
    uint8_t test_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test s2n_ktls_set_control_data and s2n_ktls_get_control_data */
    {
        /* Test: Safety */
        {
            struct msghdr msg = { 0 };
            char buf[100] = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_set_control_data(NULL, buf, sizeof(buf), 0, 0),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_set_control_data(&msg, NULL, sizeof(buf), 0, 0),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_set_control_data(&msg, buf, 0, 0, 0),
                    S2N_ERR_NULL);

            uint8_t record_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_get_control_data(NULL, 0, &record_type),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_get_control_data(&msg, 0, NULL),
                    S2N_ERR_NULL);
        };

        /* Test: s2n_ktls_set_control_data msg is parseable by s2n_ktls_get_control_data */
        {
            const uint8_t set_record_type = 5;
            struct msghdr msg = { 0 };
            const int cmsg_type = 11;
            char buf[100] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&msg, buf, sizeof(buf), cmsg_type, set_record_type));

            uint8_t get_record_type = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&msg, cmsg_type, &get_record_type));

            EXPECT_EQUAL(set_record_type, get_record_type);
        };

        /* Test: s2n_ktls_get_control_data fails with unexpected cmsg_type */
        {
            const uint8_t set_record_type = 5;
            struct msghdr msg = { 0 };
            const int cmsg_type = 11;
            char buf[100] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&msg, buf, sizeof(buf), cmsg_type, set_record_type));

            const int bad_cmsg_type = 99;
            uint8_t get_record_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_get_control_data(&msg, bad_cmsg_type, &get_record_type),
                    S2N_ERR_KTLS_BAD_CMSG);
        };
    };

    /* Test s2n_ktls_sendmsg */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);

            struct iovec msg_iov_valid = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;

            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(NULL, test_record_type, NULL, 1, &blocked, &bytes_written),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server, test_record_type, NULL, 1, &blocked, &bytes_written),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server, test_record_type, &msg_iov_valid, 1, NULL, &bytes_written),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server, test_record_type, &msg_iov_valid, 1, &blocked, NULL),
                    S2N_ERR_NULL);

            struct iovec msg_iov_null_data = { .iov_base = NULL, .iov_len = S2N_TEST_TO_SEND };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server, test_record_type, &msg_iov_null_data, 1, &blocked, &bytes_written),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Happy case: msg_iovlen = 1 */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, &msg_iov, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_ancillary(&client_in, test_record_type, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_data(&client_in, test_data, S2N_TEST_TO_SEND));

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 1);
        };

        /* Happy case: msg_iovlen > 1 */
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
            size_t bytes_written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, msg_iov, S2N_TEST_MSG_IOVLEN, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, total_sent);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_ancillary(&client_in, test_record_type, total_sent));
            EXPECT_OK(s2n_test_validate_data(&client_in, test_data, total_sent));
            /* validate only 1 record was sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_in.ancillary_buffer),
                    S2N_TEST_KTLS_MOCK_HEADER_SIZE);

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 1);
        };

        /* Simulate a blocked network and handle a S2N_ERR_IO_BLOCKED error */
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
            size_t bytes_written = 0;
            for (size_t i = 0; i < blocked_invoked_count; i++) {
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_ktls_sendmsg(server, test_record_type, &msg_iov, 1, &blocked, &bytes_written),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            }

            /* enable growable to unblock write */
            /* cppcheck-suppress redundantAssignment */
            client_in.data_buffer.growable = true;
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, &msg_iov, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_ancillary(&client_in, test_record_type, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_data(&client_in, test_data, S2N_TEST_TO_SEND));

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, blocked_invoked_count + 1);
        };

        /* Both EWOULDBLOCK and EAGAIN should return a S2N_ERR_IO_BLOCKED error */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            struct s2n_test_ktls_io_fail io_ctx = { 0 };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_fail, &io_ctx));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;

            io_ctx.errno_code = EWOULDBLOCK;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server, test_record_type, &msg_iov, 1, &blocked, &bytes_written),
                    S2N_ERR_IO_BLOCKED);

            /* cppcheck-suppress redundantAssignment */
            io_ctx.errno_code = EAGAIN;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server, test_record_type, &msg_iov, 1, &blocked, &bytes_written),
                    S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(io_ctx.invoked_count, 2);
        };

        /* Handle a S2N_ERR_IO error */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            struct s2n_test_ktls_io_fail io_ctx = {
                .errno_code = EINVAL,
            };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_fail, &io_ctx));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server, test_record_type, &msg_iov, 1, &blocked, &bytes_written),
                    S2N_ERR_IO);
            /* Blocked status intentionally not reset to preserve legacy s2n_send behavior */
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);

            EXPECT_EQUAL(io_ctx.invoked_count, 1);
        };

        /* Should be able to invoke s2n_ktls_sendmsg with '0' data */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer client_in = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(server, &client_in));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;

            size_t iovlen_zero = 0;
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, &msg_iov, iovlen_zero, &blocked, &bytes_written));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_EQUAL(bytes_written, 0);

            struct iovec msg_iov_len_zero = { .iov_base = test_data, .iov_len = 0 };
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, &msg_iov_len_zero, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_EQUAL(bytes_written, 0);

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 2);
        };
    };

    END_TEST();
}
