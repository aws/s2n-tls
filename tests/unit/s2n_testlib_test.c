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

#include "testlib/s2n_testlib.h"

#include "s2n_test.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test that s2n_negotiate_test_server_and_client produces useful errors.
     * In the past, we failed to surface errors and instead reported io errors when
     * the failed connection's peer couldn't read the next expected message.
     *
     * We should always report the actual error to allow better debugging of tests.
     */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        POSIX_GUARD(s2n_io_pair_init_non_blocking(&io_pair));
        POSIX_GUARD(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* This should NEVER fail with an error related to blocked IO. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, NULL), S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    END_TEST();
}
