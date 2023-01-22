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

    const uint8_t close_notify_alert[] = {
        2 /* AlertLevel = fatal */,
        0 /* AlertDescription = close_notify */
    };

    const uint8_t alert_record_header[] = {
        /* record type */
        TLS_ALERT,
        /* protocol version */
        S2N_TLS12 / 10,
        S2N_TLS12 % 10,
        /* length */
        0,
        S2N_ALERT_LENGTH,
    };

    /* Test: Await close_notify if no close_notify received yet */
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

    /* Test: s2n_shutdown ignores data received after a close_notify */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Receive a non-alert record */
        uint8_t record_bytes[] = {
            /* record type */
            TLS_HANDSHAKE,
            /* protocol version */
            S2N_TLS12 / 10,
            S2N_TLS12 % 10,
            /* length */
            0,
            1,
            /* data */
            'x'
        };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, record_bytes, sizeof(record_bytes)));
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Receive the response close_notify */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, alert_record_header, sizeof(alert_record_header)));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, close_notify_alert, sizeof(close_notify_alert)));
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
    };

    /* Test: s2n_shutdown with aggressive socket close */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* The client's first shutdown attempt blocks on the server's close_notify */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client_conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* The server's next shutdown succeeds.
         * From the server's perspective the connection is now gracefully shutdown and
         * the socket can be closed.
         */
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &blocked));
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        /* Even though the socket is now closed, we should be able to finish
         * shutting down the client connection too.
         */
        EXPECT_SUCCESS(s2n_shutdown(client_conn, &blocked));
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));
    };

    END_TEST();
}
