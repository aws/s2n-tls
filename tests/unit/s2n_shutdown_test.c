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

#include "tls/s2n_shutdown.c"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_alerts.h"

#define ALERT_LEN (sizeof(uint16_t))

static S2N_RESULT s2n_skip_handshake(struct s2n_connection *conn)
{
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    while (!s2n_handshake_is_complete(conn)) {
        conn->handshake.message_number++;
    }
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t close_notify_alert[] = {
        2 /* AlertLevel = fatal */,
        0 /* AlertDescription = close_notify */
    };

    /* Test: Do not wait for response close_notify if handshake not complete */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

        /* Verify state prior to alert */
        EXPECT_FALSE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(conn->close_notify_received);
        EXPECT_FALSE(conn->close_notify_queued);
        EXPECT_FALSE(conn->closed);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));

        /* Verify state after shutdown attempt */
        EXPECT_FALSE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(conn->close_notify_received);
        EXPECT_TRUE(conn->close_notify_queued);
        EXPECT_TRUE(conn->closed);
    };

    /* Test: Await close_notify if no close_notify received yet */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_skip_handshake(conn));

        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

        /* Verify state prior to alert */
        EXPECT_FALSE(conn->close_notify_received);
        EXPECT_FALSE(conn->closed);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Verify state after shutdown attempt */
        EXPECT_FALSE(conn->close_notify_received);
        EXPECT_TRUE(conn->closed);
    };

    /* Test: Do not await close_notify if close_notify already received */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_skip_handshake(conn));

        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

        /* Verify state prior to alert */
        EXPECT_FALSE(conn->close_notify_received);
        EXPECT_FALSE(conn->closed);

        /* Write and process the alert */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, close_notify_alert, sizeof(close_notify_alert)));
        EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

        /* Verify state after alert */
        EXPECT_TRUE(conn->close_notify_received);
        EXPECT_TRUE(conn->closed);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        /* Verify state after shutdown attempt */
        EXPECT_TRUE(conn->close_notify_received);
        EXPECT_TRUE(conn->closed);
    };

    END_TEST();
}
