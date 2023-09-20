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
#include "testlib/s2n_ktls_test_utils.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_alerts.h"
#include "utils/s2n_socket.h"

#define ALERT_LEN (sizeof(uint16_t))

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t close_notify_alert[] = {
        S2N_TLS_ALERT_LEVEL_WARNING,
        S2N_TLS_ALERT_CLOSE_NOTIFY
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

    const uint8_t alert_record_size = sizeof(alert_record_header) + S2N_ALERT_LENGTH;

    /* Test: Do not send or await close_notify if reader alert already queued */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_OK(s2n_skip_handshake(conn));

        /* Setup output, but no input. We expect no reads. */
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&output, conn));

        /* Verify state prior to alert */
        EXPECT_TRUE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));

        /* Queue reader alert */
        EXPECT_SUCCESS(s2n_queue_reader_handshake_failure_alert(conn));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));

        /* Verify state after shutdown attempt */
        EXPECT_TRUE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_TRUE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));

        /* Verify only one alert sent */
        EXPECT_EQUAL(s2n_stuffer_data_available(&output), alert_record_size);

        /* Verify that the single alert is a fatal error, not a close_notify */
        uint8_t level = 0, code = 0;
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&output, sizeof(alert_record_header)));
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &level));
        EXPECT_EQUAL(level, S2N_TLS_ALERT_LEVEL_FATAL);
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output, &code));
        EXPECT_EQUAL(code, S2N_TLS_ALERT_HANDSHAKE_FAILURE);
    };

    /* Test: Send and await close_notify if a warning alert was sent */
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
        EXPECT_TRUE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));

        /* Queue reader warning */
        EXPECT_OK(s2n_queue_reader_no_renegotiation_alert(conn));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked),
                S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Verify state after shutdown attempt */
        EXPECT_TRUE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_TRUE(conn->alert_sent);
        EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));

        /* Verify two alerts sent: the warning + the close_notify */
        EXPECT_EQUAL(s2n_stuffer_data_available(&output), alert_record_size * 2);
    };

    /* Test: Do not send or await close_notify if error alert was already received */
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
        EXPECT_TRUE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));

        /* Queue input alert */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, alert_record_header,
                sizeof(alert_record_header)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_TLS_ALERT_LEVEL_FATAL));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_TLS_ALERT_INTERNAL_ERROR));

        /* Receive alert */
        uint8_t buffer[1] = { 0 };
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(conn, buffer, sizeof(buffer), &blocked),
                S2N_ERR_ALERT);

        /* Call s2n_connection_get_alert(), to make sure that
         * https://github.com/aws/s2n-tls/issues/3933 doesn't affect shutdown.
         */
        EXPECT_EQUAL(s2n_connection_get_alert(conn), S2N_TLS_ALERT_INTERNAL_ERROR);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_alert(conn), S2N_ERR_NO_ALERT);

        /* Shutdown should succeed, since it's a no-op */
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));

        /* Verify state after shutdown attempt */
        EXPECT_TRUE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));

        /* Verify no alerts sent */
        EXPECT_EQUAL(s2n_stuffer_data_available(&output), 0);
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
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));

        /* Verify state after shutdown */
        EXPECT_FALSE(s2n_handshake_is_complete(conn));
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_TRUE(conn->alert_sent);

        /* Fully closed: we don't worry about truncating data */
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
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
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Verify state after shutdown attempt */
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_TRUE(conn->alert_sent);

        /* Half-close: only write closed */
        EXPECT_EQUAL(s2n_connection_get_protocol_version(conn), S2N_TLS13);
        EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
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
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));

        /* Write and process the alert */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, close_notify_alert, sizeof(close_notify_alert)));
        EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

        /* Verify state after alert */
        EXPECT_TRUE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
        EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        /* Verify state after shutdown attempt */
        EXPECT_TRUE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_TRUE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
    };

    /* Test: s2n_shutdown reports alerts received after a close_notify is sent */
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

        /* Verify s2n_shutdown is waiting for a close_notify */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        EXPECT_TRUE(conn->alert_sent);

        /* Queue an input error alert */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, alert_record_header, sizeof(alert_record_header)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, 2));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_TLS_ALERT_INTERNAL_ERROR));

        /* Receive and report the error alert */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_ALERT);

        /* Verify state after shutdown attempt */
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_TRUE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
        EXPECT_EQUAL(s2n_stuffer_data_available(&output), alert_record_size);

        /* Future calls are no-ops */
        for (size_t i = 0; i < 5; i++) {
            EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
            EXPECT_TRUE(conn->alert_sent);
        }
    };

    /* Test: s2n_shutdown ignores data received after a close_notify is sent */
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

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        EXPECT_TRUE(conn->alert_sent);

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
        EXPECT_OK(s2n_skip_handshake(server_conn));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_OK(s2n_skip_handshake(client_conn));

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

    /* Test: Do not send or await close_notify if supporting QUIC */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_enable_quic(conn));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        /* Verify state after shutdown attempt */
        EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        EXPECT_FALSE(conn->alert_sent);
        EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
    };

    /* Test: s2n_shutdown_send */
    {
        /* Test: Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown_send(NULL, &blocked), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown_send(conn, NULL), S2N_ERR_NULL);
        }

        /* Test: Basic successful call */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            /* Only setup write IO.
             * By not setting up read IO, we test that s2n_shutdown_send never
             * attempts to read.
             */
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&output, conn));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            /* s2n_shutdown also doesn't attempt to read unless we skip the
             * handshake. s2n_shutdown_send doesn't care about the state of the
             * handshake, but skip anyway to prove that.
             */
            EXPECT_OK(s2n_skip_handshake(conn));

            /* Successful half-close */
            EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_EQUAL(s2n_stuffer_data_available(&output), alert_record_size);
            EXPECT_TRUE(conn->alert_sent);
        };

        /* Test: Handles blocking IO */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            /* Do not initially allocate any memory for the output stuffer.
             * That will cause writes to block.
             */
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&output, conn));

            /* All attempts to shutdown should block */
            for (size_t i = 0; i < 5; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown_send(conn, &blocked),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                EXPECT_EQUAL(s2n_stuffer_data_available(&output), 0);
            }

            /* Once we allocate memory for the output stuffer (by marking it
             * growable here), writes should start succeeding.
             */
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

            /* Successful half-close */
            EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            EXPECT_EQUAL(s2n_stuffer_data_available(&output), alert_record_size);
            EXPECT_TRUE(conn->alert_sent);
        };

        /* Test: No-op on wipe */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_FULL_DUPLEX));
            EXPECT_FALSE(conn->alert_sent);
        };

        /* Test: Full close after half close */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_skip_handshake(conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

            /* Successful half-close.
             * Subsequent calls are no-ops.
             */
            for (size_t i = 0; i < 5; i++) {
                EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
                EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
                EXPECT_EQUAL(s2n_stuffer_data_available(&output), alert_record_size);
                EXPECT_TRUE(conn->alert_sent);
            }

            /* Full close blocks on input */
            for (size_t i = 0; i < 5; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
                EXPECT_FALSE(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
                EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_READABLE));
            }

            /* Copy alert from output to input */
            EXPECT_SUCCESS(s2n_stuffer_copy(&output, &input, s2n_stuffer_data_available(&output)));

            /* Full close succeeds.
             * Subsequent calls are no-ops.
             */
            for (size_t i = 0; i < 5; i++) {
                EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
                EXPECT_EQUAL(s2n_stuffer_data_available(&input), 0);
                EXPECT_EQUAL(s2n_stuffer_data_available(&output), 0);
                EXPECT_TRUE(conn->alert_sent);
            }
        };

        /* Test: Half close, local alert, then full close */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_skip_handshake(conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

            /* Successful half-close */
            EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(conn->alert_sent);

            /* Queue a local fatal alert */
            EXPECT_SUCCESS(s2n_queue_reader_handshake_failure_alert(conn));

            /* Full close is no-op */
            EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        };

        /* Test: Half close, peer alert, then full close */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_OK(s2n_skip_handshake(conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

            /* Successful half-close */
            EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(conn->alert_sent);

            /* Receive alert */
            uint8_t buffer[1] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, alert_record_header,
                    sizeof(alert_record_header)));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_TLS_ALERT_LEVEL_FATAL));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_TLS_ALERT_INTERNAL_ERROR));
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(conn, buffer, sizeof(buffer), &blocked),
                    S2N_ERR_ALERT);

            /* Full close is no-op */
            EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->close_notify_received));
        };

        /* Test: kTLS enabled */
        {
            /* Test: Successfully send alert */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);
                s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_SEND);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));

                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_TRUE(conn->alert_sent);
                EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
                EXPECT_OK(s2n_test_validate_ancillary(&out, TLS_ALERT, S2N_ALERT_LENGTH));
                EXPECT_OK(s2n_test_validate_data(&out,
                        close_notify_alert, sizeof(close_notify_alert)));

                /* Repeating the shutdown does not resend the alert */
                for (size_t i = 0; i < 5; i++) {
                    EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
                    EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                    EXPECT_TRUE(conn->alert_sent);
                    EXPECT_EQUAL(out.sendmsg_invoked_count, 1);
                }
            };

            /* Test: Successfully send alert after blocking */
            {
                /* One call does the partial write, the second blocks */
                const size_t partial_write = 1;
                const size_t second_write = sizeof(close_notify_alert) - partial_write;
                EXPECT_TRUE(second_write > 0);

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);
                s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_SEND);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer out = { 0 },
                        s2n_ktls_io_stuffer_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer_send(conn, &out));
                EXPECT_SUCCESS(s2n_stuffer_free(&out.data_buffer));
                EXPECT_SUCCESS(s2n_stuffer_alloc(&out.data_buffer, partial_write));

                /* One call does the partial write, the second blocks */
                size_t expected_calls = 2;

                /* Initial shutdown blocks */
                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown_send(conn, &blocked),
                        S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                EXPECT_TRUE(conn->alert_sent);
                EXPECT_EQUAL(out.sendmsg_invoked_count, expected_calls);
                EXPECT_OK(s2n_test_validate_ancillary(&out, TLS_ALERT, partial_write));
                EXPECT_OK(s2n_test_validate_data(&out, close_notify_alert, partial_write));

                /* Unblock the output stuffer */
                out.data_buffer.growable = true;
                expected_calls++;
                EXPECT_SUCCESS(s2n_stuffer_wipe(&out.ancillary_buffer));

                /* Second shutdown succeeds */
                EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_TRUE(conn->alert_sent);
                EXPECT_EQUAL(out.sendmsg_invoked_count, expected_calls);
                EXPECT_OK(s2n_test_validate_ancillary(&out, TLS_ALERT, second_write));
                EXPECT_OK(s2n_test_validate_data(&out, close_notify_alert,
                        sizeof(close_notify_alert)));

                /* Repeating the shutdown does not resend the alert */
                for (size_t i = 0; i < 5; i++) {
                    EXPECT_SUCCESS(s2n_shutdown_send(conn, &blocked));
                    EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                    EXPECT_TRUE(conn->alert_sent);
                    EXPECT_EQUAL(out.sendmsg_invoked_count, expected_calls);
                }
            };
        };
    };

    /* Test: ktls enabled */
    {
        /* Test: Successfully shutdown */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            s2n_ktls_configure_connection(client, S2N_KTLS_MODE_SEND);
            s2n_ktls_configure_connection(client, S2N_KTLS_MODE_RECV);
            EXPECT_OK(s2n_skip_handshake(client));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            s2n_ktls_configure_connection(server, S2N_KTLS_MODE_SEND);
            s2n_ktls_configure_connection(server, S2N_KTLS_MODE_RECV);
            EXPECT_OK(s2n_skip_handshake(server));

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_shutdown_send(client, &blocked));
            EXPECT_TRUE(client->alert_sent);

            EXPECT_SUCCESS(s2n_shutdown(server, &blocked));
            EXPECT_TRUE(server->alert_sent);
            EXPECT_TRUE(s2n_connection_check_io_status(server, S2N_IO_CLOSED));
        };

        /* Test: Successfully shutdown after blocking */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            s2n_ktls_configure_connection(client, S2N_KTLS_MODE_SEND);
            s2n_ktls_configure_connection(client, S2N_KTLS_MODE_RECV);
            EXPECT_OK(s2n_skip_handshake(client));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            s2n_ktls_configure_connection(server, S2N_KTLS_MODE_SEND);
            s2n_ktls_configure_connection(server, S2N_KTLS_MODE_RECV);
            EXPECT_OK(s2n_skip_handshake(server));

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            /* Setup the client->server stuffer to not fit the entire close_notify */
            EXPECT_SUCCESS(s2n_stuffer_free(&io_pair.server_in.data_buffer));
            EXPECT_SUCCESS(s2n_stuffer_alloc(&io_pair.server_in.data_buffer, 1));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            EXPECT_FALSE(s2n_connection_check_io_status(client, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(client, S2N_IO_READABLE));

            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(server, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            EXPECT_FALSE(s2n_connection_check_io_status(server, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(server, S2N_IO_READABLE));

            /* Reuse the client->server stuffer for the remaining close_notify */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.server_in.data_buffer));

            EXPECT_SUCCESS(s2n_shutdown(client, &blocked));
            EXPECT_SUCCESS(s2n_shutdown(server, &blocked));
        };

        /* Test: Skip application data when waiting for close_notify */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            s2n_ktls_configure_connection(client, S2N_KTLS_MODE_SEND);
            s2n_ktls_configure_connection(client, S2N_KTLS_MODE_RECV);
            EXPECT_OK(s2n_skip_handshake(client));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            s2n_ktls_configure_connection(server, S2N_KTLS_MODE_SEND);
            s2n_ktls_configure_connection(server, S2N_KTLS_MODE_RECV);
            EXPECT_OK(s2n_skip_handshake(server));

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair io_pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(server, client, &io_pair));

            /* Send some application data for shutdown to skip */
            uint8_t app_data[] = "hello world";
            size_t app_data_size = sizeof(app_data);
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            size_t app_data_count = 5;
            for (size_t i = 0; i < app_data_count; i++) {
                EXPECT_SUCCESS(s2n_send(client, app_data, app_data_size, &blocked));
                EXPECT_SUCCESS(s2n_send(server, app_data, app_data_size, &blocked));
            }
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.client_in, TLS_APPLICATION_DATA, app_data_size));
            EXPECT_OK(s2n_test_validate_ancillary(&io_pair.server_in, TLS_APPLICATION_DATA, app_data_size));
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.client_in, app_data_count));
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.server_in, app_data_count));

            /* Client's first shutdown blocks on reading the close_notify,
             * but successfully writes the close_notify and skips all the app data.*/
            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            EXPECT_FALSE(s2n_connection_check_io_status(client, S2N_IO_WRITABLE));
            EXPECT_TRUE(s2n_connection_check_io_status(client, S2N_IO_READABLE));
            EXPECT_TRUE(client->alert_sent);
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.client_in, 0));
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.server_in, app_data_count + 1));

            /* Server's first shutdown successfully skips all the app data
             * and receives the close_notify */
            EXPECT_SUCCESS(s2n_shutdown(server, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(server, S2N_IO_CLOSED));
            EXPECT_TRUE(server->alert_sent);
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.client_in, 1));
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.server_in, 0));

            /* Client's second shutdown successfully receives the close_notify */
            EXPECT_SUCCESS(s2n_shutdown(client, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(client, S2N_IO_CLOSED));
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.client_in, 0));
            EXPECT_OK(s2n_test_records_in_ancillary(&io_pair.server_in, 0));
        };
    };

    END_TEST();
}
