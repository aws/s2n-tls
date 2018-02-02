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
#include "tls/s2n_resume.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_server_finished_recv(struct s2n_connection *conn)
{
    uint8_t *our_version;
    int length = S2N_TLS_FINISHED_LEN;
    our_version = conn->handshake.server_finished;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = S2N_SSL_FINISHED_LEN;
    }

    uint8_t *their_version = s2n_stuffer_raw_read(&conn->handshake.io, length);
    notnull_check(their_version);

    S2N_ERROR_IF(!s2n_constant_time_equals(our_version, their_version, length), S2N_ERR_BAD_MESSAGE);

    return 0;
}

int s2n_server_finished_send(struct s2n_connection *conn)
{
    uint8_t *our_version;
    int length = S2N_TLS_FINISHED_LEN;

    /* Compute the finished message */
    GUARD(s2n_prf_server_finished(conn));

    our_version = conn->handshake.server_finished;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = S2N_SSL_FINISHED_LEN;
    }

    GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, our_version, length));

    /* Zero the sequence number */
    struct s2n_blob seq = {.data = conn->secure.server_sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_blob_zero(&seq));

    /* Update the secure state to active, and point the client at the active state */
    conn->server = &conn->secure;

    if (IS_RESUMPTION_HANDSHAKE(conn->handshake.handshake_type)) {
        GUARD(s2n_prf_key_expansion(conn));
    }

    return 0;
}
