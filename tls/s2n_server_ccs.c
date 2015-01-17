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

#include <stdint.h>

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

/* From RFC5246 7.1. */
#define CHANGE_CIPHER_SPEC_TYPE  1

int s2n_server_ccs_recv(struct s2n_connection *conn)
{
    uint8_t type;

    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, &type));
    if (type != CHANGE_CIPHER_SPEC_TYPE) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    /* Zero the sequence number */
    GUARD(s2n_zero_sequence_number(conn->pending.server_sequence_number));

    /* Update the pending state to active, and point the client at the active state */
    memcpy_check(&conn->active, &conn->pending, sizeof(conn->active));
    conn->client = &conn->active;

    /* Compute the finished message */
    GUARD(s2n_prf_server_finished(conn));

    /* Flush any partial alert messages that were pending */
    GUARD(s2n_stuffer_wipe(&conn->alert_in));

    conn->handshake.next_state = SERVER_FINISHED;

    return 0;
}

int s2n_server_ccs_send(struct s2n_connection *conn)
{
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, CHANGE_CIPHER_SPEC_TYPE));

    /* Compute the finished message */
    GUARD(s2n_prf_server_finished(conn));

    conn->handshake.next_state = SERVER_FINISHED;

    return 0;
}
