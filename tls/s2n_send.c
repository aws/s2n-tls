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

#include "utils/s2n_compiler.h"

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

ssize_t s2n_sendv(struct s2n_connection * conn, const struct iovec *bufs, ssize_t count, ssize_t offs, s2n_blocked_status * blocked)
{
    ssize_t user_data_sent;
    int max_payload_size, buf_idx, buf_offs;

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

    size_t size = 0;
    for (buf_idx = 0; buf_idx < count; buf_idx++) {
        size += bufs[buf_idx].iov_len;
    }
    size -= offs;

    /* Defensive check against an invalid retry */
    S2N_ERROR_IF(conn->current_user_data_consumed > size, S2N_ERR_SEND_SIZE);

    if (conn->dynamic_record_timeout_threshold > 0) {
        uint64_t elapsed;
        GUARD(s2n_timer_elapsed(conn->config, &conn->write_timer, &elapsed));
        /* Reset record size back to a single segment after threshold seconds of inactivity */
        if (elapsed - conn->last_write_elapsed > (uint64_t) conn->dynamic_record_timeout_threshold * 1000000000) {
            conn->active_application_bytes_consumed = 0;
        }
        conn->last_write_elapsed = elapsed;
    }

    /* Find correct buf_idx and offset within it to start operations */
    size_t user_data_consumed = offs + conn->current_user_data_consumed;
    for (buf_idx = 0, buf_offs = 0; buf_idx < count; buf_idx++) {
        if (user_data_consumed < bufs[buf_idx].iov_len) {
            buf_offs = user_data_consumed;
            break;
        }
        user_data_consumed -= bufs[buf_idx].iov_len;
    }

    /* Now write the data we were asked to send this round */
    while (size - conn->current_user_data_consumed) {
        GUARD(s2n_stuffer_rewrite(&conn->out));

        int space_remaining, space_needed;
        do {
            struct s2n_blob in = {.data = ((uint8_t *)(uintptr_t) bufs[buf_idx].iov_base) + buf_offs };
            in.size = MIN(bufs[buf_idx].iov_len - buf_offs, max_payload_size);

            /* If dynamic record size is enabled,
             * use small TLS records that fit into a single TCP segment for the threshold bytes of data     
             */
            if (conn->active_application_bytes_consumed < (uint64_t) conn->dynamic_record_resize_threshold) {
                int min_payload_size = s2n_record_min_write_payload_size(conn);
                if (min_payload_size < in.size) {
                    in.size = min_payload_size; 
                }
            }

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
            GUARD(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));
            conn->current_user_data_consumed += in.size;
            conn->active_application_bytes_consumed += in.size;

            /* increase buffer pointer */
            buf_offs += in.size;
            if (buf_offs >= bufs[buf_idx].iov_len) {
                if (++buf_idx >= count) {
                    break;
                }
                buf_offs = 0;
            }

            /* if no more space left, break */
            space_remaining = max_payload_size - conn->out.write_cursor;
            space_needed = MIN(bufs[buf_idx].iov_len - buf_offs, max_payload_size);

        } while (space_needed < space_remaining);

        /* Write out to device */
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

#if S2N_GCC_VERSION_AT_LEAST(4,6,0)
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wcast-qual"
ssize_t s2n_send(struct s2n_connection * conn, const void *buf, ssize_t size, s2n_blocked_status * blocked)
{
    struct iovec iovec;
    iovec.iov_base = (void*)buf;
    iovec.iov_len = size;
    return s2n_sendv(conn, &iovec, 1, 0, blocked);
}
#if S2N_GCC_VERSION_AT_LEAST(4,6,0)
#pragma GCC diagnostic pop
#endif

/* Code should not be added below this point if not using gcc higher than 4.6 */
