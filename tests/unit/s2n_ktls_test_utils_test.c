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

#include "testlib/s2n_ktls_test_utils.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_random.h"

#define S2N_TEST_RECORD_TYPE 43

/* Creates an iovec and sets it on new msghdr. This operation is verbose
 * and not super interesting so its captured in a macro to make the tests
 * easier to read. */
#define INIT_MSGHDR(name, buf, len)       \
    struct iovec name##_msg_iov = { 0 };  \
    name##_msg_iov.iov_base = buf;        \
    name##_msg_iov.iov_len = len;         \
    struct msghdr name##_msg = { 0 };     \
    name##_msg.msg_iov = &name##_msg_iov; \
    name##_msg.msg_iovlen = 1;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* test data */
    uint8_t test_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test the mock IO stuffer implementation can send/recv records */
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
        EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, to_send));
        /* confirm sent ancillary data */
        EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, S2N_TEST_RECORD_TYPE, to_send));
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

        EXPECT_EQUAL(io_pair.client_in.invoked_count, 2);
        EXPECT_EQUAL(io_pair.server_in.invoked_count, 0);
    };

    /* Test s2n_test_ktls_update_prev_header_len */
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
        EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, S2N_TEST_RECORD_TYPE, to_send));

        /* set new value and check again */
        for (size_t to_send_loop = 1; to_send_loop < S2N_TLS_MAXIMUM_FRAGMENT_LENGTH; to_send_loop++) {
            EXPECT_OK(s2n_test_ktls_update_prev_header_len(&io_pair.client_in, to_send_loop));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, S2N_TEST_RECORD_TYPE, to_send_loop));
        }

        /* updating len to 0 is an error */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_ktls_update_prev_header_len(&io_pair.client_in, 0), S2N_ERR_SAFETY);

        EXPECT_EQUAL(io_pair.client_in.invoked_count, 1);
        EXPECT_EQUAL(io_pair.server_in.invoked_count, 0);
    };

    END_TEST();
}
