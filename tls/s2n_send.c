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

#include <sys/param.h>
#include <errno.h>
#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_post_handshake.h"
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
        errno = 0;
        w = s2n_connection_send_stuffer(&conn->out, conn, s2n_stuffer_data_available(&conn->out));
        if (w < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                POSIX_BAIL(S2N_ERR_IO_BLOCKED);
            }
            POSIX_BAIL(S2N_ERR_IO);
        }
        conn->wire_bytes_out += w;
    }

    if (conn->closing) {
        conn->closed = 1;
    }
    POSIX_GUARD(s2n_stuffer_rewrite(&conn->out));

    /* If there's an alert pending out, send that */
    if (s2n_stuffer_data_available(&conn->reader_alert_out) == 2) {
        struct s2n_blob alert = {0};
        alert.data = conn->reader_alert_out.blob.data;
        alert.size = 2;
        POSIX_GUARD(s2n_record_write(conn, TLS_ALERT, &alert));
        POSIX_GUARD(s2n_stuffer_rewrite(&conn->reader_alert_out));
        conn->closing = 1;

        /* Actually write it ... */
        goto WRITE;
    }

    /* Do the same for writer driven alerts */
    if (s2n_stuffer_data_available(&conn->writer_alert_out) == 2) {
        struct s2n_blob alert = {0};
        alert.data = conn->writer_alert_out.blob.data;
        alert.size = 2;
        POSIX_GUARD(s2n_record_write(conn, TLS_ALERT, &alert));
        POSIX_GUARD(s2n_stuffer_rewrite(&conn->writer_alert_out));
        conn->closing = 1;

        /* Actually write it ... */
        goto WRITE;
    }

    *blocked = S2N_NOT_BLOCKED;

    return 0;
}

ssize_t s2n_sendv_with_offset_impl(struct s2n_connection *conn, const struct iovec *bufs, ssize_t count, ssize_t offs, s2n_blocked_status *blocked)
{
    ssize_t user_data_sent, total_size = 0;

    POSIX_ENSURE(!conn->closed, S2N_ERR_CLOSED);
    POSIX_ENSURE(!s2n_connection_is_quic_enabled(conn), S2N_ERR_UNSUPPORTED_WITH_QUIC);

    /* Flush any pending I/O */
    POSIX_GUARD(s2n_flush(conn, blocked));

    /* Acknowledge consumed and flushed user data as sent */
    user_data_sent = conn->current_user_data_consumed;

    *blocked = S2N_BLOCKED_ON_WRITE;

    uint16_t max_payload_size = 0;
    POSIX_GUARD_RESULT(s2n_record_max_write_payload_size(conn, &max_payload_size));

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
    if (offs) {
        const struct iovec* _bufs = bufs;
        ssize_t _count = count;
        while (offs >= _bufs->iov_len && _count > 0) {
            offs -= _bufs->iov_len;
            _bufs++;
            _count--;
        }
        bufs = _bufs;
        count = _count;
    }
    for (ssize_t i = 0; i < count; i++) {
        total_size += bufs[i].iov_len;
    }
    total_size -= offs;
    S2N_ERROR_IF(conn->current_user_data_consumed > total_size, S2N_ERR_SEND_SIZE);
    POSIX_GUARD_RESULT(s2n_early_data_validate_send(conn, total_size));

    if (conn->dynamic_record_timeout_threshold > 0) {
        uint64_t elapsed;
        POSIX_GUARD_RESULT(s2n_timer_elapsed(conn->config, &conn->write_timer, &elapsed));
        /* Reset record size back to a single segment after threshold seconds of inactivity */
        if (elapsed - conn->last_write_elapsed > (uint64_t) conn->dynamic_record_timeout_threshold * 1000000000) {
            conn->active_application_bytes_consumed = 0;
        }
        conn->last_write_elapsed = elapsed;
    }

    /* Now write the data we were asked to send this round */
    while (total_size - conn->current_user_data_consumed) {
        ssize_t to_write = MIN(total_size - conn->current_user_data_consumed, max_payload_size);

        /* If dynamic record size is enabled,
         * use small TLS records that fit into a single TCP segment for the threshold bytes of data
         */
        if (conn->active_application_bytes_consumed < (uint64_t) conn->dynamic_record_resize_threshold) {
            uint16_t min_payload_size = 0;
            POSIX_GUARD_RESULT(s2n_record_min_write_payload_size(conn, &min_payload_size));
            to_write = MIN(min_payload_size, to_write);
        }

        /* Don't split messages in server mode for interoperability with naive clients.
         * Some clients may have expectations based on the amount of content in the first record.
         */
        if (conn->actual_protocol_version < S2N_TLS11 && writer->cipher_suite->record_alg->cipher->type == S2N_CBC && conn->mode != S2N_SERVER) {
            if (to_write > 1 && cbcHackUsed == 0) {
                to_write = 1;
                cbcHackUsed = 1;
            }
        }
    
        POSIX_GUARD(s2n_stuffer_rewrite(&conn->out));

        POSIX_GUARD(s2n_post_handshake_send(conn, blocked));
    
        /* Write and encrypt the record */
        POSIX_GUARD(s2n_record_writev(conn, TLS_APPLICATION_DATA, bufs, count, 
            conn->current_user_data_consumed + offs, to_write));
        conn->current_user_data_consumed += to_write;
        conn->active_application_bytes_consumed += to_write;

        /* Send it */
        if (s2n_flush(conn, blocked) < 0) {
            if (s2n_errno == S2N_ERR_IO_BLOCKED && user_data_sent > 0) {
                /* We successfully sent >0 user bytes on the wire, but not the full requested payload
                 * because we became blocked on I/O. Acknowledge the data sent. */

                conn->current_user_data_consumed -= user_data_sent;
                return user_data_sent;
            } else {
                S2N_ERROR_PRESERVE_ERRNO();
            }
        }

        /* Acknowledge consumed and flushed user data as sent */
        user_data_sent = conn->current_user_data_consumed;
    }

    /* If everything has been written, then there's no user data pending */
    conn->current_user_data_consumed = 0;

    *blocked = S2N_NOT_BLOCKED;

    POSIX_GUARD_RESULT(s2n_early_data_record_bytes(conn, total_size));
    return total_size;
}

ssize_t s2n_sendv_with_offset(struct s2n_connection *conn, const struct iovec *bufs, ssize_t count, ssize_t offs, s2n_blocked_status *blocked)
{
    POSIX_ENSURE(!conn->send_in_use, S2N_ERR_REENTRANCY);
    conn->send_in_use = true;
    ssize_t result = s2n_sendv_with_offset_impl(conn, bufs, count, offs, blocked);
    conn->send_in_use = false;
    return result;
}

ssize_t s2n_sendv(struct s2n_connection *conn, const struct iovec *bufs, ssize_t count, s2n_blocked_status *blocked)
{
    return s2n_sendv_with_offset(conn, bufs, count, 0, blocked);
}

ssize_t s2n_send(struct s2n_connection *conn, const void *buf, ssize_t size, s2n_blocked_status *blocked)
{
    struct iovec iov;
    iov.iov_base = (void*)(uintptr_t)buf;
    iov.iov_len = size;
    return s2n_sendv_with_offset(conn, &iov, 1, 0, blocked);
}
