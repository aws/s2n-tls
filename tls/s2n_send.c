/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/param.h>
#include <errno.h>
#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_record.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_flush(struct s2n_connection *conn, s2n_blocked_status * blocked)
{
    int w;

    *blocked = S2N_BLOCKED_ON_WRITE;

    /* Write any data that's already pending */
  WRITE:
    while (s2n_stuffer_data_available(&conn->out)) {
        w = s2n_connection_send_stuffer(&conn->out, conn, s2n_stuffer_data_available(&conn->out));
        if (w < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                S2N_ERROR(S2N_ERR_BLOCKED);
            }
            S2N_ERROR(S2N_ERR_IO);
        }
        conn->wire_bytes_out += w;
    }

    if (conn->closing) {
        conn->closed = 1;
        /* Delay wiping for close_notify. s2n_shutdown() needs to wait for peer's close_notify */
        if (!conn->close_notify_queued) {
            GUARD(s2n_connection_wipe(conn));
        }
    }
    GUARD(s2n_stuffer_rewrite(&conn->out));

    /* If there's an alert pending out, send that */
    if (s2n_stuffer_data_available(&conn->reader_alert_out) == 2) {
        struct s2n_blob alert = {0};
        alert.data = conn->reader_alert_out.blob.data;
        alert.size = 2;
        GUARD(s2n_record_write(conn, TLS_ALERT, &alert));
        GUARD(s2n_stuffer_rewrite(&conn->reader_alert_out));
        conn->closing = 1;

        /* Actually write it ... */
        goto WRITE;
    }

    /* Do the same for writer driven alerts */
    if (s2n_stuffer_data_available(&conn->writer_alert_out) == 2) {
        struct s2n_blob alert = {0};
        alert.data = conn->writer_alert_out.blob.data;
        alert.size = 2;
        GUARD(s2n_record_write(conn, TLS_ALERT, &alert));
        GUARD(s2n_stuffer_rewrite(&conn->writer_alert_out));
        conn->closing = 1;

        /* Actually write it ... */
        goto WRITE;
    }

    *blocked = S2N_NOT_BLOCKED;

    return 0;
}

ssize_t s2n_send(struct s2n_connection * conn, const void *buf, ssize_t size, s2n_blocked_status * blocked)
{
    ssize_t user_data_sent;
    int max_payload_size;

    S2N_ERROR_IF(conn->closed, S2N_ERR_CLOSED);

    /* Flush any pending I/O */
    GUARD(s2n_flush(conn, blocked));

    /* Acknowledge consumed and flushed user data as sent */
    user_data_sent = conn->current_user_data_consumed;

    *blocked = S2N_BLOCKED_ON_WRITE;

    GUARD((max_payload_size = s2n_record_max_write_payload_size(conn)));

    /* TLS 1.0 and SSLv3 are vulnerable to the so-called Beast attack. Work
     * around this by splitting messages into one byte records, and then
     * the remainder can follow as usual.
     */
    int cbcHackUsed = 0;

    struct s2n_crypto_parameters *writer = conn->server;
    if (conn->mode == S2N_CLIENT) {
        writer = conn->client;
    }

    /* Defensive check against an invalid retry */
    S2N_ERROR_IF(conn->current_user_data_consumed > size, S2N_ERR_SEND_SIZE);

    /* Now write the data we were asked to send this round */
    while (size - conn->current_user_data_consumed) {
        struct s2n_blob in = {.data = ((uint8_t *)(uintptr_t) buf) + conn->current_user_data_consumed };
        in.size = MIN(size - conn->current_user_data_consumed, max_payload_size);

        /* Don't split messages in server mode for interoperability with naive clients.
         * Some clients may have expectations based on the amount of content in the first record.
         */
        if (conn->actual_protocol_version < S2N_TLS11 && writer->cipher_suite->record_alg->cipher->type == S2N_CBC && conn->mode != S2N_SERVER) {
            if (in.size > 1 && cbcHackUsed == 0) {
                in.size = 1;
                cbcHackUsed = 1;
            }
        }

        /* Write and encrypt the record */
        GUARD(s2n_stuffer_rewrite(&conn->out));
        GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
        conn->current_user_data_consumed += in.size;

        /* Send it */
        if (s2n_flush(conn, blocked) < 0) {
            if (s2n_errno == S2N_ERR_BLOCKED && user_data_sent > 0) {
                /* We successfully sent >0 user bytes on the wire, but not the full requested payload
                 * because we became blocked on I/O. Acknowledge the data sent. */

                conn->current_user_data_consumed -= user_data_sent;
                return user_data_sent;
            } else {
                return -1;
            }
        }

        /* Acknowledge consumed and flushed user data as sent */
        user_data_sent = conn->current_user_data_consumed;
    }

    /* If everything has been written, then there's no user data pending */
    conn->current_user_data_consumed = 0;

    *blocked = S2N_NOT_BLOCKED;

    return size;
}
