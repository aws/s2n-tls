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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_result.h"

bool s2n_custom_send_fn_called = false;
static int s2n_expect_concurrent_error_send_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection *) io_context;
    s2n_custom_send_fn_called = true;

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    ssize_t result = s2n_negotiate(conn, &blocked);
    EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_REENTRANCY);
    return result;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_negotiate can't be called recursively */
    {
        /* Setup connections */
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_OK(s2n_connection_set_secrets(conn));

        /* Setup bad callback */
        EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, s2n_expect_concurrent_error_send_fn));
        EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, (void *) conn));

        /* Negotiate. When we attempt to send the ClientHello, the send callback
         * should fail due to a reentrancy error.
         */
        s2n_custom_send_fn_called = false;
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_send_fn_called);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
}
