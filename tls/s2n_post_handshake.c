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

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

/* Check if a handshake message is supported by s2n-tls.
 * This includes ALL handshake messages, including messages
 * not allowed as post-handshake.
 */
bool s2n_post_handshake_is_known(uint8_t message_type)
{
    switch (message_type) {
        case TLS_SERVER_NEW_SESSION_TICKET:
        case TLS_HELLO_REQUEST:
        case TLS_KEY_UPDATE:
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
        case TLS_NPN:
            return true;
        default:
            return false;
    }
}

static S2N_RESULT s2n_post_handshake_process(struct s2n_connection *conn, struct s2n_stuffer *in, uint8_t message_type)
{
    RESULT_ENSURE_REF(conn);

    switch (message_type) {
        case TLS_KEY_UPDATE:
            RESULT_GUARD_POSIX(s2n_key_update_recv(conn, in));
            break;
        case TLS_SERVER_NEW_SESSION_TICKET:
            RESULT_GUARD(s2n_tls13_server_nst_recv(conn, in));
            break;
        case TLS_HELLO_REQUEST:
            RESULT_GUARD(s2n_client_hello_request_recv(conn));
            break;
        default:
            /* Ignore unknown messages */
            RESULT_ENSURE(!s2n_post_handshake_is_known(message_type), S2N_ERR_BAD_MESSAGE);
            break;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_post_handshake_message_recv(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    struct s2n_stuffer *in = &conn->in;
    struct s2n_stuffer *message = &conn->post_handshake.in;
    uint8_t message_type = 0;
    uint32_t message_len = 0;

    /* We always start reading from the beginning of the message */
    RESULT_GUARD_POSIX(s2n_stuffer_reread(message));

    /* If no space for the fragment exists, start with the minimum, static space */
    if (s2n_stuffer_is_freed(message)) {
        struct s2n_blob b = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&b, conn->post_handshake.in_bytes,
                sizeof(conn->post_handshake.in_bytes)));
        RESULT_GUARD_POSIX(s2n_stuffer_init(message, &b));
    }

    /* Try to read the header */
    if (s2n_stuffer_data_available(message) < TLS_HANDSHAKE_HEADER_LENGTH) {
        uint32_t remaining = TLS_HANDSHAKE_HEADER_LENGTH - s2n_stuffer_data_available(message);
        uint32_t to_read = MIN(remaining, s2n_stuffer_data_available(in));
        RESULT_GUARD_POSIX(s2n_stuffer_copy(in, message, to_read));
    }
    RESULT_ENSURE(s2n_stuffer_data_available(message) >= TLS_HANDSHAKE_HEADER_LENGTH, S2N_ERR_IO_BLOCKED);

    /* Parse the header */
    RESULT_GUARD(s2n_handshake_parse_header(message, &message_type, &message_len));
    RESULT_ENSURE(message_len == 0 || s2n_stuffer_data_available(in), S2N_ERR_IO_BLOCKED);

    /* If the message is not fragmented, just process it directly from conn->in.
     * This will be the most common case, and does not require us to allocate
     * any new memory.
     */
    if (s2n_stuffer_data_available(message) == 0 && s2n_stuffer_data_available(in) >= message_len) {
        struct s2n_stuffer full_message = { 0 };
        struct s2n_blob full_message_blob = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&full_message_blob, s2n_stuffer_raw_read(in, message_len), message_len));
        RESULT_GUARD_POSIX(s2n_stuffer_init(&full_message, &full_message_blob));
        RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&full_message, message_len));
        RESULT_GUARD(s2n_post_handshake_process(conn, &full_message, message_type));
        return S2N_RESULT_OK;
    }

    /* Skip unknown message types.
     * If we can't parse a message, there's no reason to actually allocate memory to store it.
     */
    if (!s2n_post_handshake_is_known(message_type)) {
        uint32_t to_skip = MIN(s2n_stuffer_data_available(in), message_len);
        RESULT_GUARD_POSIX(s2n_stuffer_skip_read(in, to_skip));
        if (to_skip < message_len) {
            /* Rewrite header for next fragment */
            RESULT_GUARD_POSIX(s2n_stuffer_wipe(message));
            RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(message, message_type));
            RESULT_GUARD_POSIX(s2n_stuffer_write_uint24(message, message_len - to_skip));
            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        } else {
            return S2N_RESULT_OK;
        }
    }

    /* If insufficient buffer space, resize */
    if (s2n_stuffer_space_remaining(message) < message_len) {
        /* We want to avoid servers allocating memory in response to post-handshake messages
         * to avoid a potential DDOS / resource exhaustion attack.
         *
         * Currently, s2n-tls servers only support the KeyUpdate message,
         * which should never require additional memory to parse.
         */
        RESULT_ENSURE(conn->mode == S2N_CLIENT, S2N_ERR_BAD_MESSAGE);

        uint32_t total_size = message_len + TLS_HANDSHAKE_HEADER_LENGTH;;
        if (message->alloced) {
            RESULT_GUARD_POSIX(s2n_stuffer_resize(message, total_size));
        } else {
            /* Manually convert our static stuffer to a growable stuffer */
            RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(message, total_size));
            RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(message, conn->post_handshake.in_bytes, TLS_HANDSHAKE_HEADER_LENGTH));
            RESULT_GUARD_POSIX(s2n_stuffer_skip_read(message, TLS_HANDSHAKE_HEADER_LENGTH));
        }
    }

    /* Try to read the rest of the message */
    if (s2n_stuffer_data_available(message) < message_len) {
        uint32_t remaining = message_len - s2n_stuffer_data_available(message);
        uint32_t to_read = MIN(remaining, s2n_stuffer_data_available(in));
        RESULT_GUARD_POSIX(s2n_stuffer_copy(in, message, to_read));
    }
    RESULT_ENSURE(s2n_stuffer_data_available(message) == message_len, S2N_ERR_IO_BLOCKED);

    /* Finish processing */
    RESULT_GUARD(s2n_post_handshake_process(conn, message, message_type));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_post_handshake_recv(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    while(s2n_stuffer_data_available(&conn->in)) {
        RESULT_GUARD(s2n_post_handshake_message_recv(conn));
        RESULT_GUARD_POSIX(s2n_stuffer_wipe(&conn->post_handshake.in));
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
