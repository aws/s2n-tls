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
#include "tls/s2n_alerts.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

typedef enum {
    S2N_SHUTDOWN_RDWR,
    S2N_SHUTDOWN_WR,
} s2n_shutdown_how;

static bool s2n_error_alert_received(struct s2n_connection *conn)
{
    /* We don't check s2n_connection_get_alert() or s2n_stuffer_data_available()
     * because of https://github.com/aws/s2n-tls/issues/3933.
     * We need to check if the stuffer contains an alert, regardless of its
     * read state.
     */
    if (conn->alert_in.write_cursor == 0) {
        return false;
    }
    /* Verify that the stuffer doesn't just contain a close_notify alert */
    if (conn->close_notify_received) {
        return false;
    }
    return true;
}

static bool s2n_error_alert_sent(struct s2n_connection *conn)
{
    /* Sending an alert always sets conn->write_closing: see s2n_flush() */
    if (!conn->write_closing) {
        return false;
    }
    /* Verify that the alert sent wasn't just a close_notify */
    if (conn->close_notify_queued) {
        return false;
    }
    return true;
}

int s2n_shutdown_impl(struct s2n_connection *conn, s2n_shutdown_how how,
        s2n_blocked_status *blocked)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(blocked);

    /* Treat this call as a no-op if already wiped */
    if (conn->send == NULL && conn->recv == NULL) {
        return S2N_SUCCESS;
    }

    /* Treat this call as a no-op if an error alert was already received.
     * Error alerts close the connection without any exchange of close_notify alerts. */
    if (s2n_error_alert_received(conn)) {
        return S2N_SUCCESS;
    }

    /* Enforce blinding.
     * If an application is using self-service blinding, ensure that they have
     * waited the required time before triggering the close_notify alert.
     */
    uint64_t elapsed = 0;
    POSIX_GUARD_RESULT(s2n_timer_elapsed(conn->config, &conn->write_timer, &elapsed));
    S2N_ERROR_IF(elapsed < conn->delay, S2N_ERR_SHUTDOWN_PAUSED);

    /* Flush any outstanding data or alerts */
    POSIX_GUARD(s2n_flush(conn, blocked));

    /* Error alerts close the connection without any exchange of close_notify alerts.
     * We need to check after flushing to account for any pending alerts.
     */
    if (s2n_error_alert_sent(conn)) {
        conn->read_closed = 1;
        return S2N_SUCCESS;
    }

    /**
     *= https://tools.ietf.org/rfc/rfc8446#section-6.1
     *# Each party MUST send a "close_notify" alert before closing its write
     *# side of the connection, unless it has already sent some error alert.
     */
    if (!conn->close_notify_queued) {
        POSIX_GUARD(s2n_queue_writer_close_alert_warning(conn));
        conn->close_notify_queued = 1;
        POSIX_GUARD(s2n_flush(conn, blocked));
    }

    /* If we're only closing the write side, then we've succeeded. */
    if (how == S2N_SHUTDOWN_WR) {
        return S2N_SUCCESS;
    }

    /*
     * The purpose of the peer responding to our close_notify
     * with its own close_notify is to prevent application data truncation.
     * However, application data is not a concern during the handshake.
     *
     * Additionally, decrypting alerts sent during the handshake can be error prone
     * due to different encryption keys and may lead to unnecessary error reporting
     * and unnecessary blinding.
     */
    if (!s2n_handshake_is_complete(conn)) {
        POSIX_GUARD_RESULT(s2n_connection_set_closed(conn));
        *blocked = S2N_NOT_BLOCKED;
        return S2N_SUCCESS;
    }

    /* Wait for the peer's close_notify. */
    uint8_t record_type = 0;
    int isSSLv2 = false;
    *blocked = S2N_BLOCKED_ON_READ;
    while (!conn->close_notify_received) {
        POSIX_GUARD(s2n_read_full_record(conn, &record_type, &isSSLv2));
        POSIX_ENSURE(!isSSLv2, S2N_ERR_BAD_MESSAGE);
        if (record_type == TLS_ALERT) {
            POSIX_GUARD(s2n_process_alert_fragment(conn));
        }

        /* Wipe and keep trying */
        POSIX_GUARD(s2n_stuffer_wipe(&conn->header_in));
        POSIX_GUARD(s2n_stuffer_wipe(&conn->in));
        conn->in_status = ENCRYPTED;
    }

    *blocked = S2N_NOT_BLOCKED;
    return S2N_SUCCESS;
}

int s2n_shutdown_send(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_GUARD(s2n_shutdown_impl(conn, S2N_SHUTDOWN_WR, blocked));
    return S2N_SUCCESS;
}

int s2n_shutdown(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_GUARD(s2n_shutdown_impl(conn, S2N_SHUTDOWN_RDWR, blocked));
    return S2N_SUCCESS;
}
