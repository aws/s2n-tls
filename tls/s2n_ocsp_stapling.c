/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <strings.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_safety.h"

int s2n_server_status_send(struct s2n_connection *conn)
{
    uint32_t length = conn->config->ocsp_status.size + 4;
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, length));

    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, (uint8_t)S2N_STATUS_REQUEST_OCSP));
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, conn->config->ocsp_status.size));
    GUARD(s2n_stuffer_write(&conn->handshake.io, &conn->config->ocsp_status));

    conn->handshake.next_state = SERVER_HELLO_DONE;

    if (conn->pending.cipher_suite->key_exchange_alg == S2N_DHE) {
        conn->handshake.next_state = SERVER_KEY;
    }

    return 0;
}

int s2n_server_status_recv(struct s2n_connection *conn)
{
    uint32_t length;
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &length));
    if (length < 4 || length > s2n_stuffer_data_available(&conn->handshake.io)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    uint8_t type;
    struct s2n_blob status = { .data = NULL, .size = 0 };

    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, &type));
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &status.size));
    status.data = s2n_stuffer_raw_read(&conn->handshake.io, status.size);
    notnull_check(status.data);

    if (type == S2N_STATUS_REQUEST_OCSP) {
        /* TODO: Validate it! */

    }
    conn->handshake.next_state = SERVER_HELLO_DONE;

    if (conn->pending.cipher_suite->key_exchange_alg == S2N_DHE) {
        conn->handshake.next_state = SERVER_KEY;
    }

    return 0;
}

