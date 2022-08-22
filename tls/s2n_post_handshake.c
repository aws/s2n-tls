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

static S2N_RESULT s2n_post_handshake_process(struct s2n_connection *conn, struct s2n_stuffer *in, uint8_t message_type)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(in);

    switch (message_type)
    {
        case TLS_KEY_UPDATE:
            RESULT_GUARD_POSIX(s2n_key_update_recv(conn, in));
            break;
        case TLS_SERVER_NEW_SESSION_TICKET:
            RESULT_GUARD(s2n_tls13_server_nst_recv(conn, in));
            break;
        case TLS_HELLO_REQUEST:
            RESULT_GUARD_POSIX(s2n_client_hello_request_recv(conn));
            break;
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
            RESULT_BAIL(S2N_ERR_BAD_MESSAGE);
            break;
        default:
            /* Ignore all other messages */
            break;
    }

    return S2N_RESULT_OK;
}

/*
 * Attempt to read a full handshake message.
 * If we fail, don't modify the input buffer so that we can attempt different processing.
 */
static S2N_RESULT s2n_try_read_full_handshake_message(struct s2n_connection *conn, uint8_t *message_type, uint32_t *message_len)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(message_len);

    struct s2n_stuffer in_copy = conn->in;
    if (s2n_stuffer_data_available(&in_copy) >= TLS_HANDSHAKE_HEADER_LENGTH) {
       RESULT_GUARD(s2n_handshake_parse_header(conn, &in_copy, message_type, message_len));
       if (s2n_stuffer_data_available(&in_copy) >= *message_len) {
           conn->in = in_copy;
           return S2N_RESULT_OK;
       }
    }
    RESULT_BAIL(S2N_ERR_IO_BLOCKED);
}

S2N_RESULT s2n_post_handshake_recv(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    uint8_t message_type = 0;
    uint32_t message_len = 0;

    while(s2n_stuffer_data_available(&conn->in)) {

        /* We have buffered a partial message.
         * Continue trying to read the complete message.
         */
        if (s2n_stuffer_data_available(&conn->post_handshake.in) > 0) {
            RESULT_GUARD(s2n_read_full_handshake_message(conn, &conn->post_handshake.in, &message_type));
            RESULT_GUARD(s2n_post_handshake_process(conn, &conn->post_handshake.in, message_type));
            RESULT_GUARD_POSIX(s2n_stuffer_wipe(&conn->post_handshake.in));
        }

        /* Because post-handshake messages are not necessarily common compared
         * to application data, we don't want to keep a dedicated buffer for them.
         * However, we also don't want to unnecessarily allocate large chunks of memory.
         *
         * Therefore, if the handshake message isn't fragmented, just read it from conn->in.
         * Only allocate new memory if we need to combine multiple fragments.
         */
        else if (s2n_result_is_ok(s2n_try_read_full_handshake_message(conn, &message_type, &message_len))) {
            struct s2n_blob message_blob = { 0 };
            uint8_t *message_data = s2n_stuffer_raw_read(&conn->in, message_len);
            RESULT_ENSURE_REF(message_data);
            RESULT_GUARD_POSIX(s2n_blob_init(&message_blob, message_data, message_len));

            struct s2n_stuffer message_stuffer = { 0 };
            RESULT_GUARD_POSIX(s2n_stuffer_init(&message_stuffer, &message_blob));
            RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&message_stuffer, message_len));

            RESULT_GUARD(s2n_post_handshake_process(conn, &message_stuffer, message_type));
        }

        /* If we can't read a full message, we'll need to buffer the partial message
         * so that we can read a new record.
         */
        else {
            uint32_t remaining = s2n_stuffer_data_available(&conn->in);
            RESULT_ENSURE_LTE(remaining, S2N_LARGE_RECORD_LENGTH);
            RESULT_GUARD_POSIX(s2n_stuffer_resize_if_empty(&conn->post_handshake.in, S2N_LARGE_RECORD_LENGTH));
            RESULT_GUARD_POSIX(s2n_stuffer_copy(&conn->in, &conn->post_handshake.in, remaining));
            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        }
    }

    return S2N_RESULT_OK;
}

int s2n_post_handshake_send(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_ENSURE_REF(conn);

    POSIX_GUARD(s2n_key_update_send(conn, blocked));
    POSIX_GUARD_RESULT(s2n_tls13_server_nst_send(conn, blocked));

    return S2N_SUCCESS;
}
