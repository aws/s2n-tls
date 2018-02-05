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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

/* From RFC5246 7.1. */
#define CHANGE_CIPHER_SPEC_TYPE  1

int s2n_client_ccs_recv(struct s2n_connection *conn)
{
    uint8_t type;

    GUARD(s2n_prf_client_finished(conn));

    struct s2n_blob seq = {.data = conn->secure.client_sequence_number,.size = sizeof(conn->secure.client_sequence_number) };
    GUARD(s2n_blob_zero(&seq));

    /* Update the client to use the cipher-suite */
    conn->client = &conn->secure;

    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, &type));
    S2N_ERROR_IF(type != CHANGE_CIPHER_SPEC_TYPE, S2N_ERR_BAD_MESSAGE);

    /* Flush any partial alert messages that were pending */
    GUARD(s2n_stuffer_wipe(&conn->alert_in));

    return 0;
}

int s2n_client_ccs_send(struct s2n_connection *conn)
{
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, CHANGE_CIPHER_SPEC_TYPE));

    return 0;
}
