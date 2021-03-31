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

/* Use usleep */
#define _XOPEN_SOURCE 500
#include <unistd.h>

#include <errno.h>
#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_post_handshake.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_socket.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

S2N_RESULT s2n_read_in_bytes(struct s2n_connection *conn, struct s2n_stuffer *output, uint32_t length)
{
    while (s2n_stuffer_data_available(output) < length) {
        uint32_t remaining = length - s2n_stuffer_data_available(output);

        errno = 0;
        int r = s2n_connection_recv_stuffer(output, conn, remaining);
        if (r == 0) {
            conn->closed = 1;
            RESULT_BAIL(S2N_ERR_CLOSED);
        } else if (r < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                RESULT_BAIL(S2N_ERR_IO_BLOCKED);
            }
            RESULT_BAIL(S2N_ERR_IO);
        }
        conn->wire_bytes_in += r;
    }

    return S2N_RESULT_OK;
}

int s2n_read_full_record(struct s2n_connection *conn, uint8_t * record_type, int *isSSLv2)
{
    *isSSLv2 = 0;

    /* If the record has already been decrypted, then leave it alone */
    if (conn->in_status == PLAINTEXT) {
        /* Only application data packets count as plaintext */
        *record_type = TLS_APPLICATION_DATA;
        return S2N_SUCCESS;
    }
    POSIX_GUARD(s2n_stuffer_resize_if_empty(&conn->in, S2N_LARGE_FRAGMENT_LENGTH));

    /* Read the record until we at least have a header */
    POSIX_GUARD_RESULT(s2n_read_in_bytes(conn, &conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH));

    uint16_t fragment_length;

    /* If the first bit is set then this is an SSLv2 record */
    if (conn->header_in.blob.data[0] & 0x80) {
        conn->header_in.blob.data[0] &= 0x7f;
        *isSSLv2 = 1;

        if (s2n_sslv2_record_header_parse(conn, record_type, &conn->client_protocol_version, &fragment_length) < 0) {
            POSIX_GUARD(s2n_connection_kill(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }
    } else {
        if (s2n_record_header_parse(conn, record_type, &fragment_length) < 0) {
            POSIX_GUARD(s2n_connection_kill(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }
    }

    /* Read enough to have the whole record */
    POSIX_GUARD_RESULT(s2n_read_in_bytes(conn, &conn->in, fragment_length));

    if (*isSSLv2) {
        return 0;
    }

    /* Decrypt and parse the record */
    if (s2n_record_parse(conn) < 0) {
        POSIX_GUARD(s2n_connection_kill(conn));
        S2N_ERROR_PRESERVE_ERRNO();
    }

    /* In TLS 1.3, encrypted handshake records would appear to be of record type
    * TLS_APPLICATION_DATA. The actual record content type is found after the encrypted
    * is decrypted.
    */
    if (conn->actual_protocol_version == S2N_TLS13 && *record_type == TLS_APPLICATION_DATA) {
        POSIX_GUARD(s2n_tls13_parse_record_type(&conn->in, record_type));
    }

    return 0;
}

ssize_t s2n_recv_impl(struct s2n_connection * conn, void *buf, ssize_t size, s2n_blocked_status * blocked)
{
    ssize_t bytes_read = 0;
    struct s2n_blob out = {.data = (uint8_t *) buf };

    if (conn->closed) {
        return 0;
    }
    *blocked = S2N_BLOCKED_ON_READ;

    S2N_ERROR_IF(conn->config->quic_enabled, S2N_ERR_UNSUPPORTED_WITH_QUIC);
    POSIX_GUARD_RESULT(s2n_early_data_validate_recv(conn));

    while (size && !conn->closed) {
        int isSSLv2 = 0;
        uint8_t record_type;
        int r = s2n_read_full_record(conn, &record_type, &isSSLv2);
        if (r < 0) {
            if (s2n_errno == S2N_ERR_CLOSED) {
                *blocked = S2N_NOT_BLOCKED;
                if (!bytes_read) {
                    return 0;
                } else {
                    return bytes_read;
                }
            }

            /* Don't propagate the error if we already read some bytes */
            if (s2n_errno == S2N_ERR_IO_BLOCKED && bytes_read) {
                s2n_errno = S2N_ERR_OK;
                return bytes_read;
            }

            /* If we get here, it's an error condition */
            if (s2n_errno != S2N_ERR_IO_BLOCKED && s2n_allowed_to_cache_connection(conn) && conn->session_id_len) {
                conn->config->cache_delete(conn, conn->config->cache_delete_data, conn->session_id, conn->session_id_len);
            }

            S2N_ERROR_PRESERVE_ERRNO();
        }

        S2N_ERROR_IF(isSSLv2, S2N_ERR_BAD_MESSAGE);

        if (record_type != TLS_APPLICATION_DATA) {
            switch (record_type)
            {
                case TLS_ALERT:
                    POSIX_GUARD(s2n_process_alert_fragment(conn));
                    POSIX_GUARD(s2n_flush(conn, blocked));
                    break;
                case TLS_HANDSHAKE:
                    POSIX_GUARD(s2n_post_handshake_recv(conn));
                    break;
            }
            POSIX_GUARD(s2n_stuffer_wipe(&conn->header_in));
            POSIX_GUARD(s2n_stuffer_wipe(&conn->in));
            conn->in_status = ENCRYPTED;
            continue;
        }

        out.size = MIN(size, s2n_stuffer_data_available(&conn->in));

        POSIX_GUARD(s2n_stuffer_erase_and_read(&conn->in, &out));
        bytes_read += out.size;

        out.data += out.size;
        size -= out.size;

        /* Are we ready for more encrypted data? */
        if (s2n_stuffer_data_available(&conn->in) == 0) {
            POSIX_GUARD(s2n_stuffer_wipe(&conn->header_in));
            POSIX_GUARD(s2n_stuffer_wipe(&conn->in));
            conn->in_status = ENCRYPTED;
        }

        /* If we've read some data, return it */
        if (bytes_read) {
            break;
        }
    }

    if (s2n_stuffer_data_available(&conn->in) == 0) {
        *blocked = S2N_NOT_BLOCKED;
    }

    POSIX_GUARD_RESULT(s2n_early_data_record_bytes(conn, bytes_read));
    return bytes_read;
}

ssize_t s2n_recv(struct s2n_connection * conn, void *buf, ssize_t size, s2n_blocked_status * blocked)
{
    POSIX_ENSURE(!conn->recv_in_use, S2N_ERR_REENTRANCY);
    conn->recv_in_use = true;
    ssize_t result = s2n_recv_impl(conn, buf, size, blocked);
    conn->recv_in_use = false;
    return result;
}

uint32_t s2n_peek(struct s2n_connection *conn) {
    return s2n_stuffer_data_available(&conn->in);
}

int s2n_recv_close_notify(struct s2n_connection *conn, s2n_blocked_status * blocked)
{
    uint8_t record_type;
    int isSSLv2;
    *blocked = S2N_BLOCKED_ON_READ;

    POSIX_GUARD(s2n_read_full_record(conn, &record_type, &isSSLv2));

    S2N_ERROR_IF(isSSLv2, S2N_ERR_BAD_MESSAGE);

    S2N_ERROR_IF(record_type != TLS_ALERT, S2N_ERR_SHUTDOWN_RECORD_TYPE);

    /* Only succeeds for an incoming close_notify alert */
    POSIX_GUARD(s2n_process_alert_fragment(conn));

    *blocked = S2N_NOT_BLOCKED;
    return 0;
}

