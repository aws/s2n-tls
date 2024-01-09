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

#define S2N_TEST_TO_SEND     10
#define S2N_CONTROL_BUF_SIZE 100
#define S2N_TEST_MSG_IOVLEN  5

S2N_RESULT s2n_ktls_set_control_data(struct msghdr *msg, char *buf, size_t buf_size,
        int cmsg_type, uint8_t record_type);
S2N_RESULT s2n_ktls_get_control_data(struct msghdr *msg, int cmsg_type, uint8_t *record_type);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t test_record_type = 43;
    /* test data */
    uint8_t test_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test the sendmsg mock IO stuffer implementation */
    {
        /* Happy case: server sends a single record */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, test_record_type, S2N_TEST_TO_SEND));

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(io_pair.server_in.sendmsg_invoked_count, 0);
        };

        /* Happy case: client sends a single record */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(client->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.server_in, test_data, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.server_in, test_record_type, S2N_TEST_TO_SEND));

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 0);
            EXPECT_EQUAL(io_pair.server_in.sendmsg_invoked_count, 1);
        };

        /* Send 0 bytes */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t send_zero = 0;
            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = send_zero };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, send_zero);

            /* confirm no records were sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), 0);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
        };

        /* Send msg_iovlen > 1 */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t total_sent = 0;
            struct iovec send_msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
            for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                send_msg_iov[i].iov_base = test_data + total_sent;
                send_msg_iov[i].iov_len = S2N_TEST_TO_SEND;

                total_sent += S2N_TEST_TO_SEND;
            }
            struct msghdr send_msg = { .msg_iov = send_msg_iov, .msg_iovlen = S2N_TEST_MSG_IOVLEN };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, total_sent);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, total_sent));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, test_record_type, total_sent));
            /* validate only 1 record was sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), S2N_TEST_KTLS_MOCK_HEADER_SIZE);
            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
        };

        /* Send multiple records of same type */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t records_to_send = 5;
            struct iovec send_msg_iov = { .iov_len = S2N_TEST_TO_SEND };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };

            size_t total_sent = 0;
            for (size_t i = 0; i < records_to_send; i++) {
                /* increment test data ptr */
                send_msg_iov.iov_base = test_data + total_sent;

                EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                        S2N_TLS_SET_RECORD_TYPE, test_record_type));
                ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
                EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);
                total_sent += bytes_written;
            }

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, total_sent));
            /* validate `records_to_send` records were sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), records_to_send * S2N_TEST_KTLS_MOCK_HEADER_SIZE);
            /* validate ancillary header */
            for (size_t i = 0; i < records_to_send; i++) {
                EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, test_record_type, S2N_TEST_TO_SEND));
                /* consume the header in order to then validate the next header */
                EXPECT_NOT_NULL(s2n_stuffer_raw_read(&io_pair.client_in.ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));
            }

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, records_to_send);
        };

        /* Send multiple records of different types */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t records_to_send = 5;
            struct iovec send_msg_iov = { .iov_len = S2N_TEST_TO_SEND };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };

            size_t total_sent = 0;
            for (size_t i = 0; i < records_to_send; i++) {
                /* increment test data ptr */
                send_msg_iov.iov_base = test_data + total_sent;

                EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                        S2N_TLS_SET_RECORD_TYPE, i));
                ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
                EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);
                total_sent += bytes_written;
            }

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, total_sent));
            /* validate `records_to_send` records were sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), records_to_send * S2N_TEST_KTLS_MOCK_HEADER_SIZE);
            /* validate ancillary header */
            for (size_t i = 0; i < records_to_send; i++) {
                EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, i, S2N_TEST_TO_SEND));
                /* consume the header in order to then validate the next header */
                EXPECT_NOT_NULL(s2n_stuffer_raw_read(&io_pair.client_in.ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));
            }

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, records_to_send);
        };

        /* Attempt send and expect EAGAIN error  */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));
            /* disable growable to simulate blocked/network buffer full */
            io_pair.client_in.data_buffer.growable = false;

            size_t to_send = 1;
            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = to_send };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };

            /* attempt sendmsg and expect EAGAIN */
            size_t blocked_invoked_count = 5;
            for (size_t i = 0; i < blocked_invoked_count; i++) {
                EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                        S2N_TLS_SET_RECORD_TYPE, test_record_type));
                EXPECT_EQUAL(s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg), S2N_FAILURE);
                EXPECT_EQUAL(errno, EAGAIN);
            }

            /* enable growable to unblock write */
            /* cppcheck-suppress redundantAssignment */
            io_pair.client_in.data_buffer.growable = true;
            /* attempt sendmsg again and expect success */
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, to_send);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, to_send));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, test_record_type, to_send));
            /* validate only 1 record was sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), S2N_TEST_KTLS_MOCK_HEADER_SIZE);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, blocked_invoked_count + 1);
        };

        /* Partial write with iov_len > 1 */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));
            /* disable growable and alloc enough space for only 1 iov buffer */
            io_pair.client_in.data_buffer.growable = false;
            EXPECT_SUCCESS(s2n_stuffer_alloc(&io_pair.client_in.data_buffer, S2N_TEST_TO_SEND));

            uint8_t *test_data_ptr = test_data;
            struct iovec send_msg_iov[S2N_TEST_MSG_IOVLEN] = { 0 };
            for (size_t i = 0; i < S2N_TEST_MSG_IOVLEN; i++) {
                send_msg_iov[i].iov_base = (void *) test_data_ptr;
                send_msg_iov[i].iov_len = S2N_TEST_TO_SEND;
                test_data_ptr += S2N_TEST_TO_SEND;
            }

            struct msghdr send_msg = { .msg_iov = send_msg_iov, .msg_iovlen = S2N_TEST_MSG_IOVLEN };
            char control_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, control_buf, sizeof(control_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            EXPECT_EQUAL(s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg),
                    S2N_TEST_TO_SEND);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, test_record_type, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, S2N_TEST_TO_SEND));
        };
    };

    /* Test the recvmsg mock IO stuffer implementation */
    {
        /* Happy case: test send/recv non-zero values. Sending 0 is a special case and tested separately */
        for (size_t to_send = 1; to_send < S2N_TLS_MAXIMUM_FRAGMENT_LENGTH; to_send++) {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = to_send };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char send_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, send_ctrl_buf, sizeof(send_ctrl_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, to_send);

            uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            char recv_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            struct iovec recv_msg_iov = { .iov_base = recv_buffer, .iov_len = to_send };
            struct msghdr recv_msg = {
                .msg_iov = &recv_msg_iov,
                .msg_iovlen = 1,
                .msg_control = recv_ctrl_buf,
                .msg_controllen = sizeof(recv_ctrl_buf),
            };
            ssize_t bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);
            EXPECT_EQUAL(bytes_read, to_send);
            /* confirm read data */
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buffer, to_send);
            uint8_t recv_record_type = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type));
            EXPECT_EQUAL(recv_record_type, test_record_type);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, 1);
        };

        /* Attempt read and expect EAGAIN error */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t to_send = 1;
            uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            struct iovec recv_msg_iov = { .iov_base = recv_buffer, .iov_len = to_send };
            char recv_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            struct msghdr recv_msg = {
                .msg_iov = &recv_msg_iov,
                .msg_iovlen = 1,
                .msg_control = recv_ctrl_buf,
                .msg_controllen = sizeof(recv_ctrl_buf),
            };
            /* attempting to recv data when nothing has been sent blocks */
            EXPECT_EQUAL(s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg), S2N_FAILURE);
            EXPECT_EQUAL(errno, EAGAIN);

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = to_send };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char send_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, send_ctrl_buf, sizeof(send_ctrl_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, to_send);

            /* recv all the sent data */
            ssize_t bytes_read = 0;
            bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);
            EXPECT_EQUAL(bytes_read, to_send);
            /* confirm read data */
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buffer, to_send);
            uint8_t recv_record_type = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type));
            EXPECT_EQUAL(recv_record_type, test_record_type);

            size_t blocked_invoked_count = 5;
            for (size_t i = 0; i < blocked_invoked_count; i++) {
                /* attempting to recv more data blocks */
                EXPECT_EQUAL(s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg), S2N_FAILURE);
                EXPECT_EQUAL(errno, EAGAIN);
            }

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, blocked_invoked_count + 2);
        };

        /* Read partial data: request < total sent */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t to_send = 10;
            size_t to_recv = 3;
            size_t remaining_len = to_send - to_recv;

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = to_send };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char send_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, send_ctrl_buf, sizeof(send_ctrl_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, to_send);

            uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            char recv_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            struct iovec recv_msg_iov = { .iov_base = recv_buffer, .iov_len = to_recv };
            struct msghdr recv_msg = {
                .msg_iov = &recv_msg_iov,
                .msg_iovlen = 1,
                .msg_control = recv_ctrl_buf,
                .msg_controllen = sizeof(recv_ctrl_buf),
            };
            ssize_t bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);
            EXPECT_EQUAL(bytes_read, to_recv);
            /* confirm read data */
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buffer, to_recv);
            uint8_t recv_record_type_1 = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type_1));
            EXPECT_EQUAL(recv_record_type_1, test_record_type);

            /* confirm that a single records still exists; data len is updated on partial reads */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), S2N_TEST_KTLS_MOCK_HEADER_SIZE);

            /* offset and recv remaining data of the same record type */
            recv_msg_iov.iov_base = recv_buffer + to_recv;
            recv_msg_iov.iov_len = remaining_len;
            bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);
            EXPECT_EQUAL(bytes_read, remaining_len);
            /* confirm read data */
            uint8_t recv_record_type_2 = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type_2));
            EXPECT_EQUAL(recv_record_type_2, test_record_type);

            /* validate all sent/recv data */
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buffer, to_send);
            /* confirm no more records are available for reading */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), 0);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, 2);
        };

        /* Read partial data: request > total sent */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t to_send = 10;
            size_t to_recv = 15;

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = to_send };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char send_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, send_ctrl_buf, sizeof(send_ctrl_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, to_send);

            uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            struct iovec recv_msg_iov = { .iov_base = recv_buffer, .iov_len = to_recv };
            char recv_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            struct msghdr recv_msg = {
                .msg_iov = &recv_msg_iov,
                .msg_iovlen = 1,
                .msg_control = recv_ctrl_buf,
                .msg_controllen = sizeof(recv_ctrl_buf),
            };
            ssize_t bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);

            /* confirm read data: minimum of sent and requested (to_send) */
            EXPECT_EQUAL(bytes_read, to_send);
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buffer, to_send);
            uint8_t recv_record_type = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type));
            EXPECT_EQUAL(recv_record_type, test_record_type);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, 1);
        };

        /* Read coalesced records of same type */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            /* send 2 records and recv one. send and recv total of 10 bytes */
            size_t records_to_send = 2;
            size_t to_send = 5;
            size_t to_recv = 10;

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = to_send };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char send_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, send_ctrl_buf, sizeof(send_ctrl_buf),
                    S2N_TLS_SET_RECORD_TYPE, test_record_type));
            size_t total_sent = 0;
            for (size_t i = 0; i < records_to_send; i++) {
                /* increment test data ptr */
                send_msg_iov.iov_base = test_data + total_sent;

                ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
                EXPECT_EQUAL(bytes_written, to_send);
                total_sent += bytes_written;
            }

            uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            char recv_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            struct iovec recv_msg_iov = { .iov_base = recv_buffer, .iov_len = to_recv };
            struct msghdr recv_msg = {
                .msg_iov = &recv_msg_iov,
                .msg_iovlen = 1,
                .msg_control = recv_ctrl_buf,
                .msg_controllen = sizeof(recv_ctrl_buf),
            };
            ssize_t bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);
            EXPECT_EQUAL(bytes_read, to_recv);
            uint8_t recv_record_type = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type));
            EXPECT_EQUAL(recv_record_type, test_record_type);

            /* validate all data was received */
            EXPECT_EQUAL(bytes_read, total_sent);
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buffer, bytes_read);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 2);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, 1);
        };

        /* Read doesn't coalesce records of different types */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            /* send 2 records of different types and recv 2 records in separate calls. send and recv total of 10 bytes */
            uint8_t record_type_1 = 1;
            uint8_t record_type_2 = 2;
            size_t to_send = 5;
            size_t to_recv = 10;
            size_t total_sent = 0;
            size_t total_recv = 0;

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = to_send };
            struct msghdr send_msg = { .msg_iov = &send_msg_iov, .msg_iovlen = 1 };
            char send_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            /* sendmsg record_type_1 */
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, send_ctrl_buf, sizeof(send_ctrl_buf),
                    S2N_TLS_SET_RECORD_TYPE, record_type_1));
            ssize_t bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, to_send);
            total_sent += bytes_written;
            /* sendmsg record_type_2 */
            EXPECT_OK(s2n_ktls_set_control_data(&send_msg, send_ctrl_buf, sizeof(send_ctrl_buf),
                    S2N_TLS_SET_RECORD_TYPE, record_type_2));
            send_msg_iov.iov_base = test_data + total_sent;
            bytes_written = s2n_test_ktls_sendmsg_io_stuffer(server->send_io_context, &send_msg);
            EXPECT_EQUAL(bytes_written, to_send);
            total_sent += bytes_written;

            uint8_t recv_buffer[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
            char recv_ctrl_buf[S2N_CONTROL_BUF_SIZE] = { 0 };
            struct iovec recv_msg_iov = { .iov_base = recv_buffer, .iov_len = to_recv };
            struct msghdr recv_msg = {
                .msg_iov = &recv_msg_iov,
                .msg_iovlen = 1,
                .msg_control = recv_ctrl_buf,
                .msg_controllen = sizeof(recv_ctrl_buf),
            };
            /* only recv record_type_1 even though we request more data */
            ssize_t bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);
            EXPECT_EQUAL(bytes_read, to_send);
            uint8_t recv_record_type_1 = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type_1));
            EXPECT_EQUAL(recv_record_type_1, record_type_1);
            total_recv += bytes_read;
            /* only recv record_type_2; which is all that remains */
            recv_msg_iov.iov_base = recv_buffer + bytes_read;
            bytes_read = s2n_test_ktls_recvmsg_io_stuffer(client->recv_io_context, &recv_msg);
            EXPECT_EQUAL(bytes_read, to_send);
            uint8_t recv_record_type_2 = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&recv_msg, S2N_TLS_GET_RECORD_TYPE, &recv_record_type_2));
            EXPECT_EQUAL(recv_record_type_2, record_type_2);
            total_recv += bytes_read;

            /* validate all data was received (we offset the test_data/recv_buffer so the
             * data ends up contiguous and easier to validate) */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), 0);
            EXPECT_EQUAL(total_recv, total_sent);
            EXPECT_BYTEARRAY_EQUAL(test_data, recv_buffer, total_sent);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 2);
            EXPECT_EQUAL(io_pair.client_in.recvmsg_invoked_count, 2);
        };
    };

    END_TEST();
}
