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

int s2n_flush(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    int w;

    *blocked = S2N_BLOCKED_ON_WRITE;

    /* Write any data that's already pending */
  WRITE:
    while (s2n_stuffer_data_available(&conn->out)) {
        w = s2n_stuffer_send_to_fd(&conn->out, conn->writefd, s2n_stuffer_data_available(&conn->out));
        if (w < 0) {
            if (errno == EWOULDBLOCK) {
                S2N_ERROR(S2N_ERR_BLOCKED);
            }
            S2N_ERROR(S2N_ERR_IO);
        }
        conn->wire_bytes_out += w;
    }
    if (conn->closing) {
        conn->closed = 1;
        GUARD(s2n_connection_wipe(conn));
    }
    GUARD(s2n_stuffer_rewrite(&conn->out));

    /* If there's an alert pending out, send that */
    if (s2n_stuffer_data_available(&conn->reader_alert_out) == 2) {
        struct s2n_blob alert;
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
        struct s2n_blob alert;
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

ssize_t s2n_send(struct s2n_connection *conn, void *buf, ssize_t size, s2n_blocked_status *blocked)
{
    struct s2n_blob in = {.data = buf };
    ssize_t bytes_written = 0;
    int max_payload_size;
    int w;

    if (conn->closed) {
        S2N_ERROR(S2N_ERR_CLOSED);
    }

    /* Flush any pending I/O */
    GUARD(s2n_flush(conn, blocked));

    *blocked = S2N_BLOCKED_ON_WRITE;

    GUARD((max_payload_size = s2n_record_max_write_payload_size(conn)));

    /* TLS 1.0 and SSLv3 are vulnerable to the so-called Beast attack. Work
     * around this by splitting messages into one byte records, and then
     * the remainder can follow as usual.
     */
    int cbcHackUsed = 0;

    /* Now write the data we were asked to send this round */
    while (size) {
        in.size = size;
        if (in.size > max_payload_size) {
            in.size = max_payload_size;
        }

        if (conn->actual_protocol_version < S2N_TLS11 && conn->active.cipher_suite->cipher->type == S2N_CBC) {
            if (in.size > 1 && cbcHackUsed == 0) {
                in.size = 1;
                cbcHackUsed = 1;
            }
        }

        /* Write and encrypt the record */
        GUARD(s2n_stuffer_rewrite(&conn->out));
        GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        bytes_written += in.size;

        /* Send it */
        while (s2n_stuffer_data_available(&conn->out)) {
            errno = 0;
            w = s2n_stuffer_send_to_fd(&conn->out, conn->writefd, s2n_stuffer_data_available(&conn->out));
            if (w < 0) {
                if (errno == EWOULDBLOCK) {
                    if (bytes_written) {
                        return bytes_written;
                    }
                    S2N_ERROR(S2N_ERR_BLOCKED);
                }
                S2N_ERROR(S2N_ERR_IO);
            }
            conn->wire_bytes_out += w;
        }

        in.data += in.size;
        size -= in.size;
    }

    *blocked = S2N_NOT_BLOCKED;

    return bytes_written;
}
