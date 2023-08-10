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
#include "utils/s2n_random.h"

#define S2N_TEST_TO_SEND 10

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_ktls_is_supported_on_platform()) {
        END_TEST();
    }

    uint8_t test_record_type = 44;
    /* test data */
    uint8_t test_data[S2N_TLS_MAXIMUM_FRAGMENT_LENGTH] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test send */
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
            /* sendmsg */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, &send_msg_iov, 1, &blocked, &bytes_written));
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
            /* sendmsg */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_OK(s2n_ktls_sendmsg(client, test_record_type, &send_msg_iov, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.server_in, test_data, S2N_TEST_TO_SEND));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.server_in, test_record_type, S2N_TEST_TO_SEND));

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 0);
            EXPECT_EQUAL(io_pair.server_in.sendmsg_invoked_count, 1);
        };

        /* Send 0 bytes. iovec.iov_len = 0 */
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
            /* sendmsg */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_sendmsg(server, test_record_type, &send_msg_iov, 1, &blocked, &bytes_written),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_EQUAL(bytes_written, send_zero);

            /* confirm no records were sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), 0);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 0);
        };

        /* Send 0 bytes. msghdr.msg_iovlen = 0 */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            size_t zero_count = 0;
            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            /* sendmsg */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_sendmsg(server, test_record_type, &send_msg_iov, zero_count, &blocked, &bytes_written),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_EQUAL(bytes_written, 0);

            /* confirm no records were sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), 0);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 0);
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

            uint8_t count = 5;
            size_t total_sent = 0;
            struct iovec *send_msg_iov = NULL;
            send_msg_iov = malloc(sizeof(*send_msg_iov) * count);
            for (size_t i = 0; i < count; i++) {
                send_msg_iov[i].iov_base = test_data + total_sent;
                send_msg_iov[i].iov_len = S2N_TEST_TO_SEND;

                total_sent += S2N_TEST_TO_SEND;
            }

            /* sendmsg */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, send_msg_iov, count, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, total_sent);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, total_sent));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, test_record_type, total_sent));
            /* validate only 1 record was sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), S2N_TEST_KTLS_MOCK_HEADER_SIZE);
            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 1);

            free(send_msg_iov);
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

            size_t total_sent = 0;
            for (size_t i = 0; i < records_to_send; i++) {
                /* increment test data ptr */
                send_msg_iov.iov_base = test_data + total_sent;

                /* sendmsg */
                ssize_t bytes_written = 0;
                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, &send_msg_iov, 1, &blocked, &bytes_written));
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
            size_t total_sent = 0;
            for (size_t record_type = 0; record_type < records_to_send; record_type++) {
                /* increment test data ptr */
                send_msg_iov.iov_base = test_data + total_sent;

                /* sendmsg */
                ssize_t bytes_written = 0;
                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                EXPECT_OK(s2n_ktls_sendmsg(server, record_type, &send_msg_iov, 1, &blocked, &bytes_written));
                EXPECT_EQUAL(bytes_written, S2N_TEST_TO_SEND);
                total_sent += bytes_written;
            }

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, total_sent));
            /* validate `records_to_send` records were sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), records_to_send * S2N_TEST_KTLS_MOCK_HEADER_SIZE);
            /* validate ancillary header */
            for (size_t record_type = 0; record_type < records_to_send; record_type++) {
                EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, record_type, S2N_TEST_TO_SEND));
                /* progress/consume the header validate the next header */
                EXPECT_NOT_NULL(s2n_stuffer_raw_read(&io_pair.client_in.ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));
            }

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, records_to_send);
        };

        /* Attempt send and expect S2N_ERR_IO_BLOCKED error  */
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
            /* attempt sendmsg and expect blocked error */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            for (size_t i = 0; i < 5; i++) {
                EXPECT_ERROR_WITH_ERRNO(s2n_ktls_sendmsg(server, test_record_type, &send_msg_iov, 1, &blocked, &bytes_written),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            }

            /* enable growable to unblock write */
            /* cppcheck-suppress redundantAssignment */
            io_pair.client_in.data_buffer.growable = true;
            /* attempt sendmsg again and expect success */
            EXPECT_OK(s2n_ktls_sendmsg(server, test_record_type, &send_msg_iov, 1, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, to_send);

            /* confirm sent data */
            EXPECT_OK(s2n_test_validate_data(&io_pair.client_in, test_data, to_send));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, test_record_type, to_send));
            /* validate only 1 record was sent  */
            EXPECT_EQUAL(s2n_stuffer_data_available(&io_pair.client_in.ancillary_buffer), S2N_TEST_KTLS_MOCK_HEADER_SIZE);

            EXPECT_EQUAL(io_pair.client_in.sendmsg_invoked_count, 6);
        };

        /* Attempt send and expect S2N_ERR_IO error  */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);

            /* setup sendmsg callback */
            struct s2n_test_ktls_io_fail io_ctx = {
                .invoked_count = 0
            };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_fail, &io_ctx));

            struct iovec send_msg_iov = { .iov_base = test_data, .iov_len = S2N_TEST_TO_SEND };
            /* attempt sendmsg and expect IO error */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_sendmsg(server, test_record_type, &send_msg_iov, 1, &blocked, &bytes_written),
                    S2N_ERR_IO);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_EQUAL(io_ctx.invoked_count, 1);
        };

        /* validate sent ancillary data */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);

            /* setup sendmsg callback */
            size_t to_send = 83;
            size_t count = 5;
            uint8_t record_type = 99;
            struct s2n_test_ktls_io_validate io_ctx = {
                .expected_data = test_data,
                .iov_len = to_send,
                .msg_iovlen = count,
                .record_type = record_type,
                .invoked_count = 0
            };
            EXPECT_OK(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_validate, &io_ctx));

            size_t total_sent = 0;
            struct iovec *send_msg_iov = NULL;
            send_msg_iov = malloc(sizeof(*send_msg_iov) * count);
            for (size_t i = 0; i < count; i++) {
                send_msg_iov[i].iov_base = test_data + total_sent;
                send_msg_iov[i].iov_len = to_send;

                total_sent += to_send;
            }

            /* sendmsg */
            ssize_t bytes_written = 0;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_OK(s2n_ktls_sendmsg(server, record_type, send_msg_iov, count, &blocked, &bytes_written));
            EXPECT_EQUAL(bytes_written, total_sent);

            EXPECT_EQUAL(io_ctx.invoked_count, 1);
            free(send_msg_iov);
        };
    };

    END_TEST();
}
