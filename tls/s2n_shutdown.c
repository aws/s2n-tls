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

int s2n_shutdown(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(blocked);

    /* Treat this call as a no-op if already wiped */
    if (conn->send == NULL && conn->recv == NULL) {
        return S2N_SUCCESS;
    }

    uint64_t elapsed = 0;
    POSIX_GUARD_RESULT(s2n_timer_elapsed(conn->config, &conn->write_timer, &elapsed));
    S2N_ERROR_IF(elapsed < conn->delay, S2N_ERR_SHUTDOWN_PAUSED);

    /* Queue our close_notify alert.
     * If we have already sent a close_notify, then this operation is a no-op.
     */
    POSIX_GUARD(s2n_queue_writer_close_alert_warning(conn));

    /* Flush any pending records, then send the queued close_notify. */
    POSIX_GUARD(s2n_flush(conn, blocked));

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
