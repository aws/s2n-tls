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

/* TLS 1.3 introducted several post handshake messages. This function currently only 
 * supports parsing for the KeyUpdate message. Once the other post-handshake messages
 * have been implemented, this function can be altered to include the other messages.
 */
int s2n_post_handshake_recv(struct s2n_connection *conn) 
{
    notnull_check(conn);

    uint8_t post_handshake_id;
    uint32_t message_length;
    S2N_ERROR_IF(conn->actual_protocol_version != S2N_TLS13, S2N_ERR_BAD_MESSAGE);

    GUARD(s2n_stuffer_read_uint8(&conn->in, &post_handshake_id));
    GUARD(s2n_stuffer_read_uint24(&conn->in, &message_length));

    struct s2n_blob post_handshake_blob = {0};
    uint8_t *message_data = s2n_stuffer_raw_read(&conn->in, message_length);
    notnull_check(message_data);
    GUARD(s2n_blob_init(&post_handshake_blob, message_data, message_length));

    struct s2n_stuffer post_handshake_stuffer = {0};
    GUARD(s2n_stuffer_init(&post_handshake_stuffer, &post_handshake_blob));
    GUARD(s2n_stuffer_skip_write(&post_handshake_stuffer, message_length));

    switch (post_handshake_id) 
    {
        case TLS_KEY_UPDATE:
            GUARD(s2n_key_update_recv(conn, &post_handshake_stuffer));
            break;
        default:
            /* Ignore all other messages */
            break;
    }

    return S2N_SUCCESS;
}

int s2n_post_handshake_send(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    notnull_check(conn);

    GUARD(s2n_key_update_send(conn));
    GUARD(s2n_flush(conn, blocked));
    GUARD(s2n_stuffer_rewrite(&conn->out));

    return S2N_SUCCESS;
}
