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
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_random.h"

#define S2N_TEST_TO_SEND    10
#define S2N_TEST_MSG_IOVLEN 5

S2N_RESULT s2n_ktls_set_control_data(struct msghdr *msg, char *buf, size_t buf_size,
        int cmsg_type, uint8_t record_type);
S2N_RESULT s2n_ktls_get_control_data(struct msghdr *msg, int cmsg_type, uint8_t *record_type);

/* Mock implementation used for validating failure behavior */
struct s2n_test_ktls_io_fail_ctx {
    size_t errno_code;
    size_t invoked_count;
};

static ssize_t s2n_test_ktls_sendmsg_fail(void *io_context, const struct msghdr *msg)
{
    struct s2n_test_ktls_io_fail_ctx *io_ctx = (struct s2n_test_ktls_io_fail_ctx *) io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->invoked_count++;
    errno = io_ctx->errno_code;
    return -1;
}

static ssize_t s2n_test_ktls_recvmsg_fail(void *io_context, struct msghdr *msg)
{
    POSIX_ENSURE_REF(msg);

    struct s2n_test_ktls_io_fail_ctx *io_ctx = (struct s2n_test_ktls_io_fail_ctx *) io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->invoked_count++;
    errno = io_ctx->errno_code;
    return -1;
}

static ssize_t s2n_test_ktls_recvmsg_eof(void *io_context, struct msghdr *msg)
{
    struct s2n_test_ktls_io_fail_ctx *io_ctx = (struct s2n_test_ktls_io_fail_ctx *) io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->invoked_count++;
    return 0;
}

ssize_t s2n_test_ktls_recvmsg_io_stuffer_and_ctrunc(void *io_context, struct msghdr *msg)
{
    POSIX_ENSURE_REF(msg);

    /* The stuffer mock IO is used to ensure `cmsghdr` is otherwise properly constructed
     * and that the failure occurs due to the MSG_CTRUNC flag. */
    ssize_t ret = s2n_test_ktls_recvmsg_io_stuffer(io_context, msg);
    POSIX_GUARD(ret);
    msg->msg_flags = MSG_CTRUNC;
    return ret;
}

struct s2n_test_iovecs {
    struct iovec *iovecs;
    size_t iovecs_count;
};

static S2N_CLEANUP_RESULT s2n_test_iovecs_free(struct s2n_test_iovecs *in)
{
    RESULT_ENSURE_REF(in);
    for (size_t i = 0; i < in->iovecs_count; i++) {
        RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) &in->iovecs[i].iov_base,
                in->iovecs[i].iov_len));
    }
    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) &in->iovecs,
            sizeof(struct iovec) * in->iovecs_count));
    return S2N_RESULT_OK;
}

/* Testing only with contiguous data could hide errors.
 * We should use iovecs where every buffer is allocated separately.
 */
static S2N_RESULT s2n_test_split_data(struct s2n_test_iovecs *iovecs, struct s2n_blob *data)
{
    RESULT_ENSURE_REF(iovecs);
    RESULT_ENSURE_REF(data);

    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, data));

    for (size_t i = 0; i < iovecs->iovecs_count; i++) {
        if (iovecs->iovecs[i].iov_len == 0) {
            continue;
        }
        struct s2n_blob mem = { 0 };
        RESULT_GUARD_POSIX(s2n_alloc(&mem, iovecs->iovecs[i].iov_len));
        RESULT_GUARD_POSIX(s2n_stuffer_read(&in, &mem));
        iovecs->iovecs[i].iov_base = mem.data;
    }
    RESULT_ENSURE_EQ(s2n_stuffer_data_available(&in), 0);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_new_iovecs(struct s2n_test_iovecs *iovecs,
        struct s2n_blob *data, const size_t *lens, size_t lens_count)
{
    RESULT_ENSURE_REF(iovecs);
    RESULT_ENSURE_REF(data);
    RESULT_ENSURE_REF(lens);

    size_t len_total = 0;
    for (size_t i = 0; i < lens_count; i++) {
        len_total += lens[i];
    }
    RESULT_ENSURE_LTE(len_total, data->size);

    size_t iovecs_count = lens_count;
    if (len_total < data->size) {
        iovecs_count++;
    }

    struct s2n_blob iovecs_mem = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&iovecs_mem, sizeof(struct iovec) * iovecs_count));
    RESULT_GUARD_POSIX(s2n_blob_zero(&iovecs_mem));
    iovecs->iovecs = (struct iovec *) iovecs_mem.data;
    iovecs->iovecs_count = iovecs_count;

    for (size_t i = 0; i < lens_count; i++) {
        iovecs->iovecs[i].iov_len = lens[i];
    }
    if (lens_count < iovecs_count) {
        iovecs->iovecs[lens_count].iov_len = data->size - len_total;
    }

    RESULT_GUARD(s2n_test_split_data(iovecs, data));
    return S2N_RESULT_OK;
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
            struct s2n_test_ktls_io_stuffer ctx = { 0 };
            struct iovec msg_iov_valid = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;

            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(NULL, test_record_type, &msg_iov_valid, 1, &blocked, &bytes_written),
                    S2N_ERR_IO);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(&ctx, test_record_type, NULL, 1, &blocked, &bytes_written),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(&ctx, test_record_type, &msg_iov_valid, 1, NULL, &bytes_written),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(&ctx, test_record_type, &msg_iov_valid, 1, &blocked, NULL),
                    S2N_ERR_NULL);
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
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    &msg_iov, 1, &blocked, &bytes_written));
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
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    msg_iov, S2N_TEST_MSG_IOVLEN, &blocked, &bytes_written));
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
                        s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                                &msg_iov, 1, &blocked, &bytes_written),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            }

            /* enable growable to unblock write */
            /* cppcheck-suppress redundantAssignment */
            client_in.data_buffer.growable = true;
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    &msg_iov, 1, &blocked, &bytes_written));
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
            struct s2n_test_ktls_io_fail_ctx io_ctx = { 0 };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_fail, &io_ctx));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;

            io_ctx.errno_code = EWOULDBLOCK;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                            &msg_iov, 1, &blocked, &bytes_written),
                    S2N_ERR_IO_BLOCKED);

            /* cppcheck-suppress redundantAssignment */
            io_ctx.errno_code = EAGAIN;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                            &msg_iov, 1, &blocked, &bytes_written),
                    S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(io_ctx.invoked_count, 2);
        };

        /* Handle a S2N_ERR_IO error */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            struct s2n_test_ktls_io_fail_ctx io_ctx = {
                .errno_code = EINVAL,
            };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_fail, &io_ctx));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                            &msg_iov, 1, &blocked, &bytes_written),
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
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    &msg_iov, iovlen_zero, &blocked, &bytes_written));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_EQUAL(bytes_written, 0);

            struct iovec msg_iov_len_zero = { .iov_base = test_data, .iov_len = 0 };
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    &msg_iov_len_zero, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_EQUAL(bytes_written, 0);

            EXPECT_EQUAL(client_in.sendmsg_invoked_count, 2);
        };
    };

    /* Test s2n_ktls_recvmsg */
    {
        /* Safety */
        {
            struct s2n_test_ktls_io_stuffer ctx = { 0 };
            uint8_t recv_buf[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t recv_record_type = 0;
            size_t bytes_read = 0;

            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(NULL, &recv_record_type, recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_IO);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(&ctx, NULL, recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(&ctx, &recv_record_type, NULL, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(&ctx, &recv_record_type, recv_buf, S2N_TEST_TO_SEND, NULL, &bytes_read),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(&ctx, &recv_record_type, recv_buf, S2N_TEST_TO_SEND, &blocked, NULL),
                    S2N_ERR_NULL);

            size_t to_recv_zero = 0;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(&ctx, &recv_record_type, recv_buf, to_recv_zero, &blocked, &bytes_read),
                    S2N_ERR_SAFETY);
        };

        /* Happy case: send/recv data using sendmsg/recvmsg */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    &msg_iov, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);

            uint8_t recv_buf[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            uint8_t recv_record_type = 0;
            size_t bytes_read = 0;
            EXPECT_OK(s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                    recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read));
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buf, bytes_read);
            EXPECT_EQUAL(bytes_read, bytes_written);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, 1);
        };

        /* Simulate blocked and handle a S2N_ERR_IO_BLOCKED error */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            uint8_t recv_buf[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t blocked_invoked_count = 5;
            uint8_t recv_record_type = 0;
            size_t bytes_read = 0;
            /* recv should block since there is no data */
            for (size_t i = 0; i < blocked_invoked_count; i++) {
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                                recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            }

            /* send data to unblock */
            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            size_t bytes_written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    &msg_iov, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);

            EXPECT_OK(s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                    recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read));
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buf, bytes_read);
            EXPECT_EQUAL(bytes_read, bytes_written);

            /* recv should block again since we have read all the data */
            for (size_t i = 0; i < blocked_invoked_count; i++) {
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                                recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            }

            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, (blocked_invoked_count * 2) + 1);
            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
        };

        /* Both EWOULDBLOCK and EAGAIN should return a S2N_ERR_IO_BLOCKED error */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            struct s2n_test_ktls_io_fail_ctx io_ctx = { 0 };
            EXPECT_OK(s2n_ktls_set_recvmsg_cb(client, s2n_test_ktls_recvmsg_fail, &io_ctx));

            uint8_t recv_buf[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t recv_record_type = 0;
            size_t bytes_read = 0;

            io_ctx.errno_code = EWOULDBLOCK;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                            recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* cppcheck-suppress redundantAssignment */
            io_ctx.errno_code = EAGAIN;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                            recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            EXPECT_EQUAL(io_ctx.invoked_count, 2);
        };

        /* Handle a S2N_ERR_IO error */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            struct s2n_test_ktls_io_fail_ctx io_ctx = {
                .errno_code = EINVAL,
            };
            EXPECT_OK(s2n_ktls_set_recvmsg_cb(client, s2n_test_ktls_recvmsg_fail, &io_ctx));

            uint8_t recv_buf[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t recv_record_type = 0;
            size_t bytes_read = 0;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                            recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_IO);
            /* Blocked status intentionally not reset to preserve legacy s2n_send behavior */
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            EXPECT_EQUAL(io_ctx.invoked_count, 1);
        };

        /* Simulate EOF and handle a S2N_ERR_CLOSED error */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            struct s2n_test_ktls_io_fail_ctx io_ctx = { 0 };
            EXPECT_OK(s2n_ktls_set_recvmsg_cb(client, s2n_test_ktls_recvmsg_eof, &io_ctx));

            uint8_t recv_buf[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t recv_record_type = 0;
            size_t bytes_read = 0;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                            recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_CLOSED);
            /* Blocked status intentionally not reset to preserve legacy s2n_send behavior */
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            EXPECT_EQUAL(io_ctx.invoked_count, 1);
        };

        /* Simulate control message truncated via MSG_CTRUNC flag and handle a S2N_ERR_KTLS_BAD_CMSG error */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));
            /* override the client recvmsg callback to add a MSG_CTRUNC flag to msghdr before returning */
            EXPECT_OK(s2n_ktls_set_recvmsg_cb(client, s2n_test_ktls_recvmsg_io_stuffer_and_ctrunc, &io_pair.client_in));

            struct iovec msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t bytes_written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(server->send_io_context, test_record_type,
                    &msg_iov, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);

            uint8_t recv_buf[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            uint8_t recv_record_type = 0;
            size_t bytes_read = 0;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ktls_recvmsg(client->recv_io_context, &recv_record_type,
                            recv_buf, S2N_TEST_TO_SEND, &blocked, &bytes_read),
                    S2N_ERR_KTLS_BAD_CMSG);
            /* Blocked status intentionally not reset to preserve legacy s2n_send behavior */
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, 1);
        };
    };

    /* Test s2n_ktls_send */
    {
        const size_t test_iov_lens[] = { 10, 0, 1, 5, 100, 100, 10 };

        /* Safety */
        {
            struct s2n_connection conn = { 0 };
            s2n_blocked_status blocked = 0;
            const struct iovec test_iovec = { .iov_base = &blocked, .iov_len = 1 };

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_sendv_with_offset(NULL, &test_iovec, 1, 0, &blocked),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_sendv_with_offset(&conn, NULL, 1, 0, &blocked),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_sendv_with_offset(&conn, NULL, 1, 1, &blocked),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_sendv_with_offset(&conn, &test_iovec, 1, 0, NULL),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_sendv_with_offset(&conn, &test_iovec, -1, 0, &blocked),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_sendv_with_offset(&conn, &test_iovec, 1, -1, &blocked),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: Basic send with single iovec */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

            const struct iovec test_iovec = {
                .iov_base = test_data,
                .iov_len = sizeof(test_data),
            };

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_EQUAL(
                    s2n_ktls_sendv_with_offset(conn, &test_iovec, 1, 0, &blocked),
                    sizeof(test_data));

            EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_OK(s2n_test_validate_ancillary(&out, TLS_APPLICATION_DATA, sizeof(test_data)));
            EXPECT_OK(s2n_test_validate_data(&out, test_data, sizeof(test_data)));
        };

        /* Test: Handle IO error from sendmsg */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            struct s2n_test_ktls_io_fail_ctx io_ctx = { .errno_code = EINVAL };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(conn, s2n_test_ktls_sendmsg_fail, &io_ctx));

            const struct iovec test_iovec = {
                .iov_base = test_data,
                .iov_len = sizeof(test_data),
            };

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_sendv_with_offset(conn, &test_iovec, 1, 0, &blocked),
                    S2N_ERR_IO);
            EXPECT_EQUAL(io_ctx.invoked_count, 1);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        };

        /* Test: Send nothing */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            const struct iovec test_iovec = {
                .iov_base = test_data,
                .iov_len = 0,
            };

            /* Send nothing with zero-length iovec array */
            EXPECT_EQUAL(s2n_ktls_sendv_with_offset(conn, NULL, 0, 0, &blocked), 0);
            EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_OK(s2n_test_records_in_ancillary(&out, 0));

            /* Send nothing with iovec array with zero-length buffer */
            EXPECT_EQUAL(s2n_ktls_sendv_with_offset(conn, &test_iovec, 1, 0, &blocked), 0);
            EXPECT_EQUAL(out.sendmsg_invoked_count, 2);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_OK(s2n_test_records_in_ancillary(&out, 0));
        };

        /* Test: Send with multiple iovecs */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

            DEFER_CLEANUP(struct s2n_test_iovecs test_iovecs = { 0 }, s2n_test_iovecs_free);
            EXPECT_OK(s2n_test_new_iovecs(&test_iovecs, &test_data_blob,
                    test_iov_lens, s2n_array_len(test_iov_lens)));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t result = s2n_ktls_sendv_with_offset(conn,
                    test_iovecs.iovecs, test_iovecs.iovecs_count, 0, &blocked);
            EXPECT_EQUAL(result, sizeof(test_data));

            EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_OK(s2n_test_validate_ancillary(&out, TLS_APPLICATION_DATA, sizeof(test_data)));
            EXPECT_OK(s2n_test_validate_data(&out, test_data, sizeof(test_data)));
        };

        /* Test: Send with offset */
        {
            DEFER_CLEANUP(struct s2n_test_iovecs test_iovecs = { 0 }, s2n_test_iovecs_free);
            EXPECT_OK(s2n_test_new_iovecs(&test_iovecs, &test_data_blob,
                    test_iov_lens, s2n_array_len(test_iov_lens)));

            size_t large_test_iov_lens[100] = { 0 };
            EXPECT_MEMCPY_SUCCESS(large_test_iov_lens, test_iov_lens, sizeof(test_iov_lens));

            DEFER_CLEANUP(struct s2n_test_iovecs large_test_iovecs = { 0 },
                    s2n_test_iovecs_free);
            EXPECT_OK(s2n_test_new_iovecs(&large_test_iovecs, &test_data_blob,
                    large_test_iov_lens, s2n_array_len(large_test_iov_lens)));

            /* Test: Send with invalid / too large offset */
            {
                const size_t bad_offset = sizeof(test_data) + 1;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                ssize_t result = s2n_ktls_sendv_with_offset(conn, large_test_iovecs.iovecs,
                        large_test_iovecs.iovecs_count, bad_offset, &blocked);
                EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_INVALID_ARGUMENT);

                EXPECT_EQUAL(out.sendmsg_invoked_count, 0);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_OK(s2n_test_records_in_ancillary(&out, 0));
            };

            /* Test: Send with offset equal to total data size */
            {
                const size_t offset = sizeof(test_data);

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                int written = s2n_ktls_sendv_with_offset(conn, large_test_iovecs.iovecs,
                        large_test_iovecs.iovecs_count, offset, &blocked);
                EXPECT_EQUAL(written, 0);

                EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_OK(s2n_test_records_in_ancillary(&out, 0));
            };

            /* Test: Send with small iovecs array and all possible valid offsets */
            for (size_t offset = 0; offset < sizeof(test_data); offset++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

                const size_t expected_sent = sizeof(test_data) - offset;
                EXPECT_TRUE(expected_sent > 0);

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                ssize_t result = s2n_ktls_sendv_with_offset(conn,
                        test_iovecs.iovecs, test_iovecs.iovecs_count, offset, &blocked);
                EXPECT_EQUAL(result, expected_sent);

                EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_OK(s2n_test_validate_ancillary(&out, TLS_APPLICATION_DATA, expected_sent));
                EXPECT_OK(s2n_test_validate_data(&out, test_data + offset, expected_sent));
            }

            /* Test: Send with large iovecs array and all possible valid offsets */
            for (size_t offset = 0; offset < sizeof(test_data); offset++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

                const size_t expected_sent = sizeof(test_data) - offset;
                EXPECT_TRUE(expected_sent > 0);

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                ssize_t result = s2n_ktls_sendv_with_offset(conn, large_test_iovecs.iovecs,
                        large_test_iovecs.iovecs_count, offset, &blocked);
                EXPECT_EQUAL(result, expected_sent);

                EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_OK(s2n_test_validate_ancillary(&out, TLS_APPLICATION_DATA, expected_sent));
                EXPECT_OK(s2n_test_validate_data(&out, test_data + offset, expected_sent));
            }
        };

        /* Test: Partial write */
        {
            DEFER_CLEANUP(struct s2n_test_iovecs test_iovecs = { 0 }, s2n_test_iovecs_free);
            EXPECT_OK(s2n_test_new_iovecs(&test_iovecs, &test_data_blob,
                    test_iov_lens, s2n_array_len(test_iov_lens)));

            /* Test with all possible partial write lengths */
            for (size_t size = 1; size < sizeof(test_data); size++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));
                EXPECT_SUCCESS(s2n_stuffer_free(&out.data_buffer));
                EXPECT_SUCCESS(s2n_stuffer_alloc(&out.data_buffer, size));

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                ssize_t result = s2n_ktls_sendv_with_offset(conn,
                        test_iovecs.iovecs, test_iovecs.iovecs_count, 0, &blocked);
                EXPECT_EQUAL(result, size);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

                EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
                EXPECT_OK(s2n_test_validate_data(&out, test_data, size));
            }
        };

        /* Test: IO would block */
        {
            DEFER_CLEANUP(struct s2n_test_iovecs test_iovecs = { 0 }, s2n_test_iovecs_free);
            EXPECT_OK(s2n_test_new_iovecs(&test_iovecs, &test_data_blob,
                    test_iov_lens, s2n_array_len(test_iov_lens)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            struct s2n_test_ktls_io_fail_ctx io_ctx = { .errno_code = EAGAIN };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(conn, s2n_test_ktls_sendmsg_fail, &io_ctx));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t result = s2n_ktls_sendv_with_offset(conn,
                    test_iovecs.iovecs, test_iovecs.iovecs_count, 0, &blocked);
            EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(io_ctx.invoked_count, 1);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
        };

        /* Test: Memory usage */
        {
            const size_t iov_lens[100] = { 10, 5, 0, 1, 100, 100, 10 };
            const size_t small_iov_lens_count = 10;
            const size_t large_iov_lens_count = s2n_array_len(iov_lens);

            DEFER_CLEANUP(struct s2n_test_iovecs small_iovecs = { 0 }, s2n_test_iovecs_free);
            EXPECT_OK(s2n_test_new_iovecs(&small_iovecs, &test_data_blob,
                    iov_lens, small_iov_lens_count));

            DEFER_CLEANUP(struct s2n_test_iovecs large_iovecs = { 0 }, s2n_test_iovecs_free);
            EXPECT_OK(s2n_test_new_iovecs(&large_iovecs, &test_data_blob,
                    iov_lens, large_iov_lens_count));

            const size_t one_iovec_size = sizeof(struct iovec);
            const size_t large_iovecs_size = large_iovecs.iovecs_count * one_iovec_size;

            struct {
                struct s2n_test_iovecs *iovecs;
                size_t offset;
                uint32_t expected_malloc;
                uint32_t expected_malloc_count;
            } test_cases[] = {
                /* Small iovecs never require an allocation */
                {
                        .iovecs = &small_iovecs,
                        .offset = 1,
                        .expected_malloc_count = 0,
                },
                {
                        .iovecs = &small_iovecs,
                        .offset = iov_lens[0],
                        .expected_malloc_count = 0,
                },
                {
                        .iovecs = &small_iovecs,
                        .offset = iov_lens[0] + 1,
                        .expected_malloc_count = 0,
                },
                /* Large iovecs with offset evenly divisible by the iov_lens do
                 * not require an alloc.
                 * Example: { x, y, z }, offset=x -> { y, z }
                 */
                {
                        .iovecs = &large_iovecs,
                        .offset = iov_lens[0],
                        .expected_malloc_count = 0,
                },
                {
                        .iovecs = &large_iovecs,
                        .offset = iov_lens[0] + iov_lens[1],
                        .expected_malloc_count = 0,
                },
                /* Large iovecs with offset not evenly divisible by the iov_lens
                 * modify an entry so require an alloc.
                 * Example: { x, y, z }, offset=1 -> { x-1, y, z }
                 */
                {
                        .iovecs = &large_iovecs,
                        .offset = 1,
                        .expected_malloc_count = 1,
                        .expected_malloc = large_iovecs_size,
                },
                {
                        .iovecs = &large_iovecs,
                        .offset = iov_lens[0] + 1,
                        .expected_malloc_count = 1,
                        .expected_malloc = large_iovecs_size - one_iovec_size,
                },
                /* Large iovecs that become small iovecs when the offset
                 * is applied do not require an alloc.
                 */
                {
                        .iovecs = &large_iovecs,
                        .offset = sizeof(test_data) - 1,
                        .expected_malloc_count = 0,
                },
                /* No alloc if the entire large iovec is skipped */
                {
                        .iovecs = &large_iovecs,
                        .offset = sizeof(test_data),
                        .expected_malloc_count = 0,
                },
            };

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                struct iovec *iovecs = test_cases[i].iovecs->iovecs;
                const size_t iovecs_count = test_cases[i].iovecs->iovecs_count;
                const size_t offset = test_cases[i].offset;

                const size_t expected_send = sizeof(test_data) - offset;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

                /* Preemptively allocate sendmsg memory to avoid false positives */
                EXPECT_SUCCESS(s2n_stuffer_resize(&out.data_buffer, expected_send));
                EXPECT_SUCCESS(s2n_stuffer_resize(&out.ancillary_buffer, 100));

                DEFER_CLEANUP(struct s2n_mem_test_cb_scope scope = { 0 },
                        s2n_mem_test_free_callbacks);
                EXPECT_OK(s2n_mem_test_init_callbacks(&scope));

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                ssize_t result = s2n_ktls_sendv_with_offset(conn, iovecs, iovecs_count,
                        offset, &blocked);
                EXPECT_EQUAL(result, sizeof(test_data) - offset);

                size_t malloc_count = test_cases[i].expected_malloc_count;
                EXPECT_OK(s2n_mem_test_assert_malloc_count(malloc_count));
                if (malloc_count) {
                    EXPECT_OK(s2n_mem_test_assert_malloc(test_cases[i].expected_malloc));
                }
                EXPECT_OK(s2n_mem_test_assert_all_freed());
            }
        };
    };

    /* Test: s2n_ktls_send_cb */
    {
        /* It's safe to reuse a connection across tests because the connection
         * isn't actually used by s2n_ktls_send_cb. It's just required for test
         * setup methods.
         */
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        /* Safety */
        {
            struct s2n_test_ktls_io_stuffer ctx = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send_cb(NULL, test_data, 1), S2N_ERR_IO);
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send_cb(&ctx, NULL, 1), S2N_ERR_IO);
        };

        /* Test: Basic write succeeds */
        {
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer ctx = { 0 },
                    s2n_ktls_io_stuffer_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &ctx));

            EXPECT_SUCCESS(s2n_ktls_send_cb(&ctx, test_data, sizeof(test_data)));
            EXPECT_EQUAL(ctx.sendmsg_invoked_count, 1);
            EXPECT_OK(s2n_test_validate_ancillary(&ctx, TLS_ALERT, sizeof(test_data)));
            EXPECT_OK(s2n_test_validate_data(&ctx, test_data, sizeof(test_data)));
        };

        /* Test: Errors passed on to caller */
        {
            struct s2n_test_ktls_io_fail_ctx ctx = { 0 };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(conn, s2n_test_ktls_sendmsg_fail, &ctx));

            ctx.errno_code = 1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send_cb(&ctx, test_data, sizeof(test_data)),
                    S2N_ERR_IO);

            ctx.errno_code = EINVAL;
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send_cb(&ctx, test_data, sizeof(test_data)),
                    S2N_ERR_IO);

            ctx.errno_code = EAGAIN;
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send_cb(&ctx, test_data, sizeof(test_data)),
                    S2N_ERR_IO_BLOCKED);

            ctx.errno_code = EWOULDBLOCK;
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_send_cb(&ctx, test_data, sizeof(test_data)),
                    S2N_ERR_IO_BLOCKED);
        };
    };

    /* Test: s2n_ktls_record_writev */
    {
        const size_t to_write = 10;

        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            struct iovec iov = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_record_writev(NULL, 0, &iov, 1, 1, 1),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_record_writev(conn, 0, NULL, 1, 1, 1),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_ktls_record_writev(conn, 0, &iov, -1, 1, 1),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: Basic write succeeds */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            struct iovec iov = {
                .iov_base = test_data,
                .iov_len = sizeof(test_data),
            };
            EXPECT_EQUAL(s2n_ktls_record_writev(conn, TLS_ALERT, &iov, 1, 0, to_write), to_write);
            EXPECT_EQUAL(conn->out.blob.allocated, to_write);
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->out), to_write);
            uint8_t *in_out = s2n_stuffer_raw_read(&conn->out, to_write);
            EXPECT_BYTEARRAY_EQUAL(in_out, test_data, to_write);
        };

        /* Test: Only alerts currently supported */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            struct iovec iov = {
                .iov_base = test_data,
                .iov_len = sizeof(test_data),
            };
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_ktls_record_writev(conn, TLS_HANDSHAKE, &iov, 1, 0, to_write),
                    S2N_ERR_UNIMPLEMENTED);
        };
    };

    END_TEST();
}
