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
    GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, message_length));
    if (post_handshake_id == TLS_KEY_UPDATE) {
        GUARD(s2n_key_update_recv(conn));
    }
    GUARD(s2n_stuffer_wipe(&conn->handshake.io));
    return 0;
}
