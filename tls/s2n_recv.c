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

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_socket.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_read_full_record(struct s2n_connection *conn, uint8_t * record_type, int *isSSLv2)
{
    int r;

    *isSSLv2 = 0;

    /* If the record has already been decrypted, then leave it alone */
    if (conn->in_status == PLAINTEXT) {
        /* Only application data packets count as plaintext */
        *record_type = TLS_APPLICATION_DATA;
        return 0;
    }
    GUARD(s2n_stuffer_resize_if_empty(&conn->in, S2N_LARGE_FRAGMENT_LENGTH));

    /* Read the record until we at least have a header */
    while (s2n_stuffer_data_available(&conn->header_in) < S2N_TLS_RECORD_HEADER_LENGTH) {
        int remaining = S2N_TLS_RECORD_HEADER_LENGTH - s2n_stuffer_data_available(&conn->header_in);

        if (s2n_connection_is_managed_corked(conn)) {
            GUARD(s2n_socket_set_read_size(conn, remaining));
        }
        r = s2n_connection_recv_stuffer(&conn->header_in, conn, remaining);

        if (r == 0) {
            conn->closed = 1;
            S2N_ERROR(S2N_ERR_CLOSED);
        } else if (r < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                S2N_ERROR(S2N_ERR_BLOCKED);
            }
            S2N_ERROR(S2N_ERR_IO);
        }
        conn->wire_bytes_in += r;
    }
    uint16_t fragment_length;

    /* If the first bit is set then this is an SSLv2 record */
    if (conn->header_in.blob.data[0] & 0x80) {
        conn->header_in.blob.data[0] &= 0x7f;
        *isSSLv2 = 1;

        if (s2n_sslv2_record_header_parse(conn, record_type, &conn->client_protocol_version, &fragment_length) < 0) {
            GUARD(s2n_connection_kill(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }
    } else {
        if (s2n_record_header_parse(conn, record_type, &fragment_length) < 0) {
            GUARD(s2n_connection_kill(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }
    }

    /* Read enough to have the whole record */
    while (s2n_stuffer_data_available(&conn->in) < fragment_length) {
        int remaining = fragment_length - s2n_stuffer_data_available(&conn->in);

        if (s2n_connection_is_managed_corked(conn)) {
            GUARD(s2n_socket_set_read_size(conn, remaining));
        }

        r = s2n_connection_recv_stuffer(&conn->in, conn, remaining);

        if (r == 0) {
            conn->closed = 1;
            S2N_ERROR(S2N_ERR_CLOSED);
        } else if (r < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                S2N_ERROR(S2N_ERR_BLOCKED);
            }
            S2N_ERROR(S2N_ERR_IO);
        }
        conn->wire_bytes_in += r;
    }

    if (*isSSLv2) {
        return 0;
    }

    /* Decrypt and parse the record */
    if (s2n_record_parse(conn) < 0) {
        GUARD(s2n_connection_kill(conn));
        S2N_ERROR_PRESERVE_ERRNO();
    }

    /* In TLS 1.3, encrypted handshake records would appear to be of record type
    * TLS_APPLICATION_DATA. The actual record content type is found after the encrypted
    * is decrypted.
    */
    if (conn->actual_protocol_version == S2N_TLS13 && *record_type == TLS_APPLICATION_DATA) {
        GUARD(s2n_parse_record_type(&conn->in, record_type));
    }

    return 0;
}

ssize_t s2n_recv(struct s2n_connection * conn, void *buf, ssize_t size, s2n_blocked_status * blocked)
{
    ssize_t bytes_read = 0;
    struct s2n_blob out = {.data = (uint8_t *) buf };

    if (conn->closed) {
        return 0;
    }

    *blocked = S2N_BLOCKED_ON_READ;

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
            if (s2n_errno == S2N_ERR_BLOCKED && bytes_read) {
                s2n_errno = S2N_ERR_OK;
                return bytes_read;
            }

            /* If we get here, it's an error condition */
            if (s2n_errno != S2N_ERR_BLOCKED && s2n_allowed_to_cache_connection(conn) && conn->session_id_len) {
                conn->config->cache_delete(conn, conn->config->cache_delete_data, conn->session_id, conn->session_id_len);
            }

            S2N_ERROR_PRESERVE_ERRNO();
        }

        S2N_ERROR_IF(isSSLv2, S2N_ERR_BAD_MESSAGE);

        if (record_type != TLS_APPLICATION_DATA) {
            if (record_type == TLS_ALERT) {
                GUARD(s2n_process_alert_fragment(conn));
                GUARD(s2n_flush(conn, blocked));
            }

            GUARD(s2n_stuffer_wipe(&conn->header_in));
            GUARD(s2n_stuffer_wipe(&conn->in));
            conn->in_status = ENCRYPTED;
            continue;
        }

        out.size = MIN(size, s2n_stuffer_data_available(&conn->in));

        GUARD(s2n_stuffer_erase_and_read(&conn->in, &out));
        bytes_read += out.size;

        out.data += out.size;
        size -= out.size;

        /* Are we ready for more encrypted data? */
        if (s2n_stuffer_data_available(&conn->in) == 0) {
            GUARD(s2n_stuffer_wipe(&conn->header_in));
            GUARD(s2n_stuffer_wipe(&conn->in));
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

    return bytes_read;
}

uint32_t s2n_peek(struct s2n_connection *conn) {
    return s2n_stuffer_data_available(&conn->in);
}

int s2n_recv_close_notify(struct s2n_connection *conn, s2n_blocked_status * blocked)
{
    uint8_t record_type;
    int isSSLv2;
    *blocked = S2N_BLOCKED_ON_READ;

    GUARD(s2n_read_full_record(conn, &record_type, &isSSLv2));

    S2N_ERROR_IF(isSSLv2, S2N_ERR_BAD_MESSAGE);

    S2N_ERROR_IF(record_type != TLS_ALERT, S2N_ERR_SHUTDOWN_RECORD_TYPE);

    /* Only succeeds for an incoming close_notify alert */
    GUARD(s2n_process_alert_fragment(conn));

    *blocked = S2N_NOT_BLOCKED;
    return 0;
}

