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

#include <unistd.h>
#include <errno.h>
#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_read_full_record(struct s2n_connection *conn, uint8_t *record_type, int *isSSLv2, const char **err)
{
    int r;

    *isSSLv2 = 0;

    /* If the record has already been decrypted, then leave it alone */
    if (conn->in_status == PLAINTEXT) {
        /* Only application data packets count as plaintext */
        *record_type = TLS_APPLICATION_DATA;
        return 0;
    }

    /* Read the record until we at least have a header */
    while (s2n_stuffer_data_available(&conn->header_in) < S2N_TLS_RECORD_HEADER_LENGTH) {
        r = s2n_stuffer_recv_from_fd(&conn->header_in, conn->readfd, S2N_TLS_RECORD_HEADER_LENGTH - s2n_stuffer_data_available(&conn->header_in), err);
        if (r == 0) {
            *err = "EOF from remote end";
            return -2;
        }
        if (r < 0) {
            return -1;
        }
        conn->wire_bytes_in += r;
    }

    uint16_t fragment_length;

    /* If the first bit is set then this is an SSLv2 record */
    if (conn->header_in.blob.data[0] & 0x80) {
        conn->header_in.blob.data[0] &= 0x7f;
        *isSSLv2 = 1;

        if (s2n_sslv2_record_header_parse(conn, record_type, &conn->client_protocol_version, &fragment_length, err) < 0) {
            conn->closed = 1;
            GUARD(s2n_connection_wipe(conn, err));
            return -1;
        }
    } else {
        if (s2n_record_header_parse(conn, record_type, &fragment_length, err) < 0) {
            conn->closed = 1;
            GUARD(s2n_connection_wipe(conn, err));
            return -1;
        }
    }

    /* Read enough to have the whole record */
    while (s2n_stuffer_data_available(&conn->in) < fragment_length) {
        r = s2n_stuffer_recv_from_fd(&conn->in, conn->readfd, fragment_length - s2n_stuffer_data_available(&conn->in), err);
        if (r == 0) {
            *err = "EOF from remote end";
            return -2;
        }
        if (r < 0) {
            return -1;
        }
        conn->wire_bytes_in += r;
    }

    if (*isSSLv2) {
        return 0;
    }

    /* Decrypt and parse the record */
    if (s2n_record_parse(conn, err) < 0) {
        conn->closed = 1;
        GUARD(s2n_connection_wipe(conn, err));

        if (conn->blinding == S2N_BUILT_IN_BLINDING) {
            int delay;
            GUARD(delay = s2n_connection_get_delay(conn, err)); 
            GUARD(usleep(delay));
        }

        return -1;
    }

    return 0;
}

ssize_t s2n_recv(struct s2n_connection *conn, void *buf, ssize_t size, int *more, const char **err)
{
    ssize_t bytes_read = 0;
    struct s2n_blob out = {.data = (uint8_t *) buf };

    if (conn->closed) {
        return 0;
    }

    *more = 1;

    while (size && !conn->closed) {
        int isSSLv2 = 0;
        uint8_t record_type;
        errno = 0;
        int r = s2n_read_full_record(conn, &record_type, &isSSLv2, err);
        if (r < 0) {
            if (errno == EWOULDBLOCK) {
                if (bytes_read) {
                    return bytes_read;
                }
                return -1;
            }
            if (r == -2) {
                conn->closed = 1;
                GUARD(s2n_connection_wipe(conn, err));
                return bytes_read;
            }
            return -1;
        }
    
        if (isSSLv2) {
            *err = "SSLv2 record detected";
            return -1;
        }
        
        if (record_type != TLS_APPLICATION_DATA) {
            if (record_type == TLS_ALERT) {
                GUARD(s2n_process_alert_fragment(conn, err));
                GUARD(s2n_flush(conn, more, err));
            }

            GUARD(s2n_stuffer_wipe(&conn->header_in, err));
            GUARD(s2n_stuffer_wipe(&conn->in, err));
            conn->in_status = ENCRYPTED;
            continue;
        }

        out.size = size;
        if (out.size > s2n_stuffer_data_available(&conn->in)) {
            out.size = s2n_stuffer_data_available(&conn->in);
        }

        GUARD(s2n_stuffer_erase_and_read(&conn->in, &out, err));
        bytes_read += out.size;

        out.data += out.size;
        size -= out.size;

        /* Are we ready for more encrypted data? */
        if (s2n_stuffer_data_available(&conn->in) == 0) {
            GUARD(s2n_stuffer_wipe(&conn->header_in, err));
            GUARD(s2n_stuffer_wipe(&conn->in, err));
            conn->in_status = ENCRYPTED;
        }

        /* If we've read some data, return it */
        if (bytes_read) {
            break;
        }
    }

    if (s2n_stuffer_data_available(&conn->in) == 0) {
        *more = 0;
    }

    return bytes_read;
}
