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
#include "tls/s2n_tls13_handshake.h"

#include "utils/s2n_safety.h"

const uint8_t S2N_KEY_UPDATE_NOT_REQUESTED = 0;
const uint8_t S2N_KEY_UPDATE_REQUESTED = 1;

int s2n_key_update_recv(struct s2n_connection *conn)
{
    notnull_check(conn);
    uint8_t key_update_request;
    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, &key_update_request));
    S2N_ERROR_IF(key_update_request != S2N_KEY_UPDATE_NOT_REQUESTED && key_update_request != S2N_KEY_UPDATE_REQUESTED,
            S2N_ERR_BAD_MESSAGE);
    conn->key_update_pending = key_update_request;
    /* Update peer's key since a key_update was received */
    if (conn->mode == S2N_CLIENT){
        GUARD(s2n_update_application_traffic_keys(conn, S2N_SERVER, RECEIVING));
    } else {
        GUARD(s2n_update_application_traffic_keys(conn, S2N_CLIENT, RECEIVING));
    }

    return 0;
}
