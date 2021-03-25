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

#include <s2n.h>

#include "tls/s2n_alerts.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_safety.h"

int s2n_shutdown(struct s2n_connection *conn, s2n_blocked_status * more)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(more);

    /* Treat this call as a no-op if already wiped */
    if (conn->send == NULL && conn->recv == NULL) {
        return 0;
    }

    uint64_t elapsed;
    POSIX_GUARD_RESULT(s2n_timer_elapsed(conn->config, &conn->write_timer, &elapsed));
    S2N_ERROR_IF(elapsed < conn->delay, S2N_ERR_SHUTDOWN_PAUSED);

    /* Queue our close notify, once. Use warning level so clients don't give up */
    POSIX_GUARD(s2n_queue_writer_close_alert_warning(conn));

    /* Write it */
    POSIX_GUARD(s2n_flush(conn, more));

    /* Assume caller isn't interested in pending incoming data */
    if (conn->in_status == PLAINTEXT) {
        POSIX_GUARD(s2n_stuffer_wipe(&conn->header_in));
        POSIX_GUARD(s2n_stuffer_wipe(&conn->in));
        conn->in_status = ENCRYPTED;
    }

    /* Dont expect to receive another close notify alert if we have already received it */
    if (!conn->close_notify_received) {
        /* Fails with S2N_ERR_SHUTDOWN_RECORD_TYPE or S2N_ERR_ALERT on receipt of anything but a close_notify */
        POSIX_GUARD(s2n_recv_close_notify(conn, more));
    }

    return 0;
}
