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

#include <stdint.h>
#include <sys/param.h>

#include "error/s2n_errno.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_alerts.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

#define S2N_TLS_ALERT_CLOSE_NOTIFY          0
#define S2N_TLS_ALERT_UNEXPECTED_MSG        10
#define S2N_TLS_ALERT_BAD_RECORD_MAC        20
#define S2N_TLS_ALERT_DECRYPT_FAILED        21
#define S2N_TLS_ALERT_RECORD_OVERFLOW       22
#define S2N_TLS_ALERT_DECOMP_FAILED         30
#define S2N_TLS_ALERT_HANDSHAKE_FAILURE     40
#define S2N_TLS_ALERT_NO_CERTIFICATE        41
#define S2N_TLS_ALERT_BAD_CERTIFICATE       42
#define S2N_TLS_ALERT_UNSUPPORTED_CERT      43
#define S2N_TLS_ALERT_CERT_REVOKED          44
#define S2N_TLS_ALERT_CERT_EXPIRED          45
#define S2N_TLS_ALERT_CERT_UNKNOWN          46
#define S2N_TLS_ALERT_ILLEGAL_PARAMETER     47
#define S2N_TLS_ALERT_UNKNOWN_CA            48
#define S2N_TLS_ALERT_ACCESS_DENIED         49
#define S2N_TLS_ALERT_DECODE_ERROR          50
#define S2N_TLS_ALERT_DECRYPT_ERROR         51
#define S2N_TLS_ALERT_EXPORT_RESTRICTED     60
#define S2N_TLS_ALERT_PROTOCOL_VERSION      70
#define S2N_TLS_ALERT_INSUFFICIENT_SECURITY 71
#define S2N_TLS_ALERT_INTERNAL_ERROR        80
#define S2N_TLS_ALERT_USER_CANCELED         90
#define S2N_TLS_ALERT_NO_RENEGOTIATION      100
#define S2N_TLS_ALERT_UNSUPPORTED_EXTENSION 110

#define S2N_TLS_ALERT_LEVEL_WARNING         1
#define S2N_TLS_ALERT_LEVEL_FATAL           2

static bool s2n_alerts_supported(struct s2n_connection *conn)
{
    /* If running in QUIC mode, QUIC handles alerting.
     * S2N should not send or receive alerts. */
    return conn && conn->config && !conn->config->quic_enabled;
}

static bool s2n_handle_as_warning(struct s2n_connection *conn, uint8_t level, uint8_t type)
{
    /* Only TLS1.2 considers the alert level. The alert level field is
     * considered deprecated in TLS1.3. */
    if (s2n_connection_get_protocol_version(conn) < S2N_TLS13) {
        return level == S2N_TLS_ALERT_LEVEL_WARNING
                && conn->config->alert_behavior == S2N_ALERT_IGNORE_WARNINGS;
    }

    /* user_canceled is the only alert currently treated as a warning in TLS1.3.
     * We need to treat it as a warning regardless of alert_behavior to avoid marking
     * correctly-closed connections as failed. */
    return type == S2N_TLS_ALERT_USER_CANCELED;
}

int s2n_process_alert_fragment(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    S2N_ERROR_IF(s2n_stuffer_data_available(&conn->in) == 0, S2N_ERR_BAD_MESSAGE);
    S2N_ERROR_IF(s2n_stuffer_data_available(&conn->alert_in) == 2, S2N_ERR_ALERT_PRESENT);
    POSIX_ENSURE(s2n_alerts_supported(conn), S2N_ERR_BAD_MESSAGE);

    while (s2n_stuffer_data_available(&conn->in)) {
        uint8_t bytes_required = 2;

        /* Alerts are two bytes long, but can still be fragmented or coalesced */
        if (s2n_stuffer_data_available(&conn->alert_in) == 1) {
            bytes_required = 1;
        }

        int bytes_to_read = MIN(bytes_required, s2n_stuffer_data_available(&conn->in));

        POSIX_GUARD(s2n_stuffer_copy(&conn->in, &conn->alert_in, bytes_to_read));

        if (s2n_stuffer_data_available(&conn->alert_in) == 2) {

            /* Close notifications are handled as shutdowns */
            if (conn->alert_in_data[1] == S2N_TLS_ALERT_CLOSE_NOTIFY) {
                conn->closed = 1;
                conn->close_notify_received = true;
                return 0;
            }

            /* Ignore warning-level alerts if we're in warning-tolerant mode */
            if (s2n_handle_as_warning(conn, conn->alert_in_data[0], conn->alert_in_data[1])) {
                POSIX_GUARD(s2n_stuffer_wipe(&conn->alert_in));
                return 0;
            }

            /* RFC 5077 5.1 - Expire any cached session on an error alert */
            if (s2n_allowed_to_cache_connection(conn) && conn->session_id_len) {
                conn->config->cache_delete(conn, conn->config->cache_delete_data, conn->session_id, conn->session_id_len);
            }

            /* All other alerts are treated as fatal errors */
            conn->closed = 1;
            POSIX_BAIL(S2N_ERR_ALERT);
        }
    }

    return 0;
}

int s2n_queue_writer_close_alert_warning(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    uint8_t alert[2];
    alert[0] = S2N_TLS_ALERT_LEVEL_WARNING;
    alert[1] = S2N_TLS_ALERT_CLOSE_NOTIFY;

    struct s2n_blob out = {.data = alert,.size = sizeof(alert) };

    /* If there is an alert pending or we've already sent a close_notify, do nothing */
    if (s2n_stuffer_data_available(&conn->writer_alert_out) || conn->close_notify_queued) {
        return S2N_SUCCESS;
    }

    if (!s2n_alerts_supported(conn)) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD(s2n_stuffer_write(&conn->writer_alert_out, &out));
    conn->close_notify_queued = 1;

    return S2N_SUCCESS;
}

static int s2n_queue_reader_alert(struct s2n_connection *conn, uint8_t level, uint8_t error_code)
{
    POSIX_ENSURE_REF(conn);

    uint8_t alert[2];
    alert[0] = level;
    alert[1] = error_code;

    struct s2n_blob out = {.data = alert,.size = sizeof(alert) };

    /* If there is an alert pending, do nothing */
    if (s2n_stuffer_data_available(&conn->reader_alert_out)) {
        return S2N_SUCCESS;
    }

    if (!s2n_alerts_supported(conn)) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD(s2n_stuffer_write(&conn->reader_alert_out, &out));

    return S2N_SUCCESS;
}

int s2n_queue_reader_unsupported_protocol_version_alert(struct s2n_connection *conn)
{
    return s2n_queue_reader_alert(conn, S2N_TLS_ALERT_LEVEL_FATAL, S2N_TLS_ALERT_PROTOCOL_VERSION);
}

int s2n_queue_reader_handshake_failure_alert(struct s2n_connection *conn)
{
    return s2n_queue_reader_alert(conn, S2N_TLS_ALERT_LEVEL_FATAL, S2N_TLS_ALERT_HANDSHAKE_FAILURE);
}
