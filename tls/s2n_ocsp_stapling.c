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
    uint32_t length = conn->config->cert_and_key_pairs->ocsp_status.size + 4;
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, length));

    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, (uint8_t) S2N_STATUS_REQUEST_OCSP));
    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, conn->config->cert_and_key_pairs->ocsp_status.size));
    GUARD(s2n_stuffer_write(&conn->handshake.io, &conn->config->cert_and_key_pairs->ocsp_status));

    return 0;
}

int s2n_server_status_recv(struct s2n_connection *conn)
{
    uint8_t type;
    struct s2n_blob status = {.data = NULL,.size = 0 };

    GUARD(s2n_stuffer_read_uint8(&conn->handshake.io, &type));
    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &status.size));
    status.data = s2n_stuffer_raw_read(&conn->handshake.io, status.size);
    notnull_check(status.data);

    if (type == S2N_STATUS_REQUEST_OCSP) {
        GUARD(s2n_alloc(&conn->status_response, status.size));
        memcpy_check(conn->status_response.data, status.data, status.size);
        conn->status_response.size = status.size;
    }

    return 0;
}
