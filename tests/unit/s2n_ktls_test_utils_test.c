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
#include "utils/s2n_random.h"

#define S2N_TEST_RECORD_TYPE 43

#define INIT_MSGHDR(name, buf, len)       \
    struct iovec name##_msg_iov = { 0 };  \
    name##_msg_iov.iov_base = buf;        \
    name##_msg_iov.iov_len = len;         \
    struct msghdr name##_msg = { 0 };     \
    name##_msg.msg_iov = &name##_msg_iov; \
    name##_msg.msg_iovlen = 1;

S2N_RESULT s2n_test_init_ktls_stuffer_io(struct s2n_connection *server, struct s2n_connection *client,
        struct s2n_test_ktls_io_pair *io_pair)
{
    RESULT_ENSURE_REF(server);
    RESULT_ENSURE_REF(client);
    RESULT_ENSURE_REF(io_pair);
    /* setup stuffer IO */
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->server_in.data_buffer, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->server_in.ancillary_buffer, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->client_in.data_buffer, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->client_in.ancillary_buffer, 0));

    RESULT_GUARD(s2n_ktls_set_send_recv_msg_fn(s2n_test_ktls_sendmsg_stuffer_io, s2n_test_ktls_recvmsg_stuffer_io));
    RESULT_GUARD(s2n_ktls_set_send_recv_msg_ctx(server, &io_pair->client_in, &io_pair->server_in));
    RESULT_GUARD(s2n_ktls_set_send_recv_msg_ctx(client, &io_pair->server_in, &io_pair->client_in));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_validate_ancillary_data(struct s2n_stuffer *ancillary_buffer, uint8_t record_type, uint16_t len)
{
    RESULT_ENSURE_REF(ancillary_buffer);
    /* create expected ancillary header */
    RESULT_STACK_BLOB(expected_ancillary, S2N_TEST_KTLS_MOCK_HEADER_SIZE, S2N_TEST_KTLS_MOCK_HEADER_SIZE);
    struct s2n_stuffer expected_ancillary_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&expected_ancillary_stuffer, &expected_ancillary));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&expected_ancillary_stuffer, record_type));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&expected_ancillary_stuffer, len));

    /* verify ancillary data */
    uint8_t *ancillary_ptr = s2n_stuffer_raw_read(ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE);
    RESULT_ENSURE_REF(ancillary_ptr);
    RESULT_ENSURE_EQ(memcmp(ancillary_ptr, expected_ancillary_buf, S2N_TEST_KTLS_MOCK_HEADER_SIZE), 0);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* test data */
    uint8_t test_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test the test. Tests the mock IO stuffer implementation */
    for (size_t to_send = 1; to_send < S2N_TLS_MAXIMUM_FRAGMENT_LENGTH; to_send++) {
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_ktls_io_pair io_pair = { 0 },
                s2n_ktls_io_pair_free);
        EXPECT_OK(s2n_test_init_ktls_stuffer_io(server, client, &io_pair));

        /* Init send msghdr */
        INIT_MSGHDR(send, test_data, to_send);
        /* sendmsg */
        ssize_t bytes_written = s2n_test_ktls_sendmsg_stuffer_io(server, &send_msg, S2N_TEST_RECORD_TYPE);
        EXPECT_EQUAL(bytes_written, to_send);

        /* confirm sent data */
        uint8_t *data_ptr = s2n_stuffer_raw_read(&io_pair.client_in.data_buffer, to_send);
        EXPECT_NOT_NULL(data_ptr);
        EXPECT_EQUAL(memcmp(test_data, data_ptr, to_send), 0);
        /* confirm sent ancillary data */
        EXPECT_OK(s2n_test_validate_ancillary_data(&io_pair.client_in.ancillary_buffer, S2N_TEST_RECORD_TYPE, to_send));
        /* rewind the read so that the recvmsg can retrieve it */
        EXPECT_SUCCESS(s2n_stuffer_rewind_read(&io_pair.client_in.data_buffer, to_send));
        EXPECT_SUCCESS(s2n_stuffer_rewind_read(&io_pair.client_in.ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));

        /* Init recv msghdr */
        uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
        INIT_MSGHDR(recv, recv_buffer, to_send);
        /* recvmsg */
        uint8_t recv_record_type = 0;
        ssize_t bytes_read = s2n_test_ktls_recvmsg_stuffer_io(client, &recv_msg, &recv_record_type);
        EXPECT_EQUAL(bytes_read, to_send);
        /* confirm read data */
        EXPECT_EQUAL(memcmp(test_data, recv_buffer, to_send), 0);
        EXPECT_EQUAL(recv_record_type, S2N_TEST_RECORD_TYPE);
    };

    /* rewrite mock header */
    {
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_test_ktls_io_pair io_pair = { 0 },
                s2n_ktls_io_pair_free);
        EXPECT_OK(s2n_test_init_ktls_stuffer_io(server, client, &io_pair));
        size_t to_send = 10;

        /* Init send msghdr */
        INIT_MSGHDR(send, test_data, to_send);
        /* sendmsg */
        ssize_t bytes_written = s2n_test_ktls_sendmsg_stuffer_io(server, &send_msg, S2N_TEST_RECORD_TYPE);
        EXPECT_EQUAL(bytes_written, to_send);

        /* confirm sent ancillary data */
        EXPECT_OK(s2n_test_validate_ancillary_data(&io_pair.client_in.ancillary_buffer, S2N_TEST_RECORD_TYPE, to_send));

        /* set new value and check again */
        for (size_t to_send_loop = 1; to_send_loop < S2N_TLS_MAXIMUM_FRAGMENT_LENGTH; to_send_loop++) {
            EXPECT_OK(s2n_test_ktls_rewrite_prev_header_len(&io_pair.client_in, to_send_loop));
            EXPECT_OK(s2n_test_validate_ancillary_data(&io_pair.client_in.ancillary_buffer, S2N_TEST_RECORD_TYPE, to_send_loop));
        }

        /* updating len to 0 is an error */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_ktls_rewrite_prev_header_len(&io_pair.client_in, 0), S2N_ERR_SAFETY);
    };

    END_TEST();
}
