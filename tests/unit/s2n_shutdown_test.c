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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t close_notify_alert[] = { 2 /* AlertLevel = fatal */,
        0 /* AlertDescription = close_notify */ };

    /* Test s2n_shutdown */
    {
        /* Await close_notify if close_notify_received is not set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer input;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            struct s2n_stuffer output;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->close_notify_received);

            s2n_blocked_status blocked;
            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* Verify state after shutdown attempt */
            EXPECT_FALSE(conn->close_notify_received);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
        }

        /* Do not await close_notify if close_notify_received is set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer input;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            struct s2n_stuffer output;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->close_notify_received);

            /* Write and process the alert */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, close_notify_alert, sizeof(close_notify_alert)));
            EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

            /* Verify state after alert */
            EXPECT_TRUE(conn->close_notify_received);

            s2n_blocked_status blocked;
            EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* Verify state after shutdown attempt */
            EXPECT_TRUE(conn->close_notify_received);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
        }
    }

    END_TEST();
}
