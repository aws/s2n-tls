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

int s2n_client_finished_recv(struct s2n_connection *conn)
{
    uint8_t *our_version;
    our_version = conn->handshake.client_finished;
    uint8_t *their_version = s2n_stuffer_raw_read(&conn->handshake.io, S2N_TLS_FINISHED_LEN);
    notnull_check(their_version);

    S2N_ERROR_IF(!s2n_constant_time_equals(our_version, their_version, S2N_TLS_FINISHED_LEN) || conn->handshake.rsa_failed, S2N_ERR_BAD_MESSAGE);

    return 0;
}

int s2n_client_finished_send(struct s2n_connection *conn)
{
    uint8_t *our_version;
    GUARD(s2n_prf_client_finished(conn));

    struct s2n_blob seq = {.data = conn->secure.client_sequence_number,.size = sizeof(conn->secure.client_sequence_number) };
    GUARD(s2n_blob_zero(&seq));
    our_version = conn->handshake.client_finished;

    /* Update the server to use the cipher suite */
    conn->client = &conn->secure;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, our_version, S2N_SSL_FINISHED_LEN));
    } else {
        GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, our_version, S2N_TLS_FINISHED_LEN));
    }
    return 0;
}
