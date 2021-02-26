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

#include <s2n.h>

bool s2n_custom_recv_fn_called = false;

int s2n_expect_concurrent_error_recv_fn(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_recv_fn_called = true;

    s2n_blocked_status blocked = 0;
    ssize_t result = s2n_recv(conn, buf, len, &blocked);
    EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_REENTRANCY);
    return result;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_recv cannot be called concurrently */
    {
        /* Setup connection */
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Setup bad recv callback */
        EXPECT_SUCCESS(s2n_connection_set_recv_cb(conn, s2n_expect_concurrent_error_recv_fn));
        EXPECT_SUCCESS(s2n_connection_set_recv_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        uint8_t test_data[100] = { 0 };
        s2n_blocked_status blocked = 0;
        s2n_custom_recv_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_recv_fn_called);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
