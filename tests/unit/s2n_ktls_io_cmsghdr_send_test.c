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

    };

    END_TEST();
}
