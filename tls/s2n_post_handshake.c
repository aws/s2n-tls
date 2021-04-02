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

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

int s2n_post_handshake_recv(struct s2n_connection *conn) 
{
    POSIX_ENSURE_REF(conn);

    uint8_t post_handshake_id;
    uint32_t message_length;
    S2N_ERROR_IF(conn->actual_protocol_version != S2N_TLS13, S2N_ERR_BAD_MESSAGE);

    while(s2n_stuffer_data_available(&conn->in)) {
        POSIX_GUARD(s2n_stuffer_read_uint8(&conn->in, &post_handshake_id));
        POSIX_GUARD(s2n_stuffer_read_uint24(&conn->in, &message_length));

        struct s2n_blob post_handshake_blob = { 0 };
        uint8_t *message_data = s2n_stuffer_raw_read(&conn->in, message_length);
        POSIX_ENSURE_REF(message_data);
        POSIX_GUARD(s2n_blob_init(&post_handshake_blob, message_data, message_length));

        struct s2n_stuffer post_handshake_stuffer = { 0 };
        POSIX_GUARD(s2n_stuffer_init(&post_handshake_stuffer, &post_handshake_blob));
        POSIX_GUARD(s2n_stuffer_skip_write(&post_handshake_stuffer, message_length));

        switch (post_handshake_id)
        {
            case TLS_KEY_UPDATE:
                POSIX_GUARD(s2n_key_update_recv(conn, &post_handshake_stuffer));
                break;
            case TLS_SERVER_NEW_SESSION_TICKET:
                POSIX_GUARD_RESULT(s2n_tls13_server_nst_recv(conn, &post_handshake_stuffer));
                break;
            case TLS_HELLO_REQUEST:
            case TLS_CLIENT_HELLO:
            case TLS_SERVER_HELLO:
            case TLS_END_OF_EARLY_DATA:
            case TLS_ENCRYPTED_EXTENSIONS:
            case TLS_CERTIFICATE:
            case TLS_SERVER_KEY:
            case TLS_CERT_REQ:
            case TLS_SERVER_HELLO_DONE:
            case TLS_CERT_VERIFY:
            case TLS_CLIENT_KEY:
            case TLS_FINISHED:
            case TLS_SERVER_CERT_STATUS:
                /* All other known handshake messages should be rejected */
                POSIX_BAIL(S2N_ERR_BAD_MESSAGE);
                break;
            default:
                /* Ignore all other messages */
                break;
        }
    }

    return S2N_SUCCESS;
}

int s2n_post_handshake_send(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_ENSURE_REF(conn);

    POSIX_GUARD(s2n_key_update_send(conn, blocked));
    POSIX_GUARD_RESULT(s2n_tls13_server_nst_send(conn, blocked));

    return S2N_SUCCESS;
}
