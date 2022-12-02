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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_connection *client_conn, *server_conn;
    s2n_blocked_status server_blocked, client_blocked;

    /* Verify successful shutdown. Server initiated. */
    {
        /* Setup connections */
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Verify state prior to alert */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        /* Verify successful shutdown */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(server_conn, &server_blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_SUCCESS(s2n_shutdown(client_conn, &client_blocked));
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));

        /* Verify state after alert */
        EXPECT_TRUE(server_conn->close_notify_received);
        EXPECT_TRUE(client_conn->close_notify_received);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    /* Verify successful shutdown. Client initiated. */
    {
        /* Setup connections */
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Verify state prior to alert */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        /* Verify successful shutdown. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client_conn, &client_blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));
        EXPECT_SUCCESS(s2n_shutdown(client_conn, &client_blocked));

        /* Verify state after alert */
        EXPECT_TRUE(server_conn->close_notify_received);
        EXPECT_TRUE(client_conn->close_notify_received);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    END_TEST();
}
