/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <errno.h>

#include <s2n.h>

int fake_recv(void *io_context, uint8_t *buf, uint32_t len)
{
    /* Pretend that we have no data availible to read for alert lookup. */
    errno = EAGAIN;
    return -1;
}

int fake_send(void *io_context, const uint8_t *buf, uint32_t len)
{
    /* Fail the write with non-retriable error. */
    errno = ENOENT;
    return -1;
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    s2n_blocked_status blocked;

    BEGIN_TEST();

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

    /* Set custom recv/send callbacks. */
    EXPECT_SUCCESS(s2n_connection_set_recv_cb(conn, &fake_recv));
    EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, &fake_send));

    /* Perform the handshake and expect an error from write, instead of error from alert read. */
    EXPECT_EQUAL(s2n_negotiate(conn, &blocked), -1);
    EXPECT_EQUAL(errno, ENOENT);
    EXPECT_EQUAL(s2n_errno, S2N_ERR_IO);

    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
