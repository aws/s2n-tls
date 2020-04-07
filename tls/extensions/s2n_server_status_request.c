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

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/extensions/s2n_server_status_request.h"

int s2n_server_extensions_status_request_send_size(struct s2n_connection *conn) {
    if (s2n_server_can_send_ocsp(conn)) {
        return 2 * sizeof(uint16_t);
    }

    return 0;
}

/* Write OCSP extension */
int s2n_server_extensions_status_request_send(struct s2n_connection *conn, struct s2n_stuffer *out) {
    if (s2n_server_can_send_ocsp(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_STATUS_REQUEST));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    return 0;
}

int s2n_recv_server_status_request(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    conn->status_type = S2N_STATUS_REQUEST_OCSP;

    return 0;
}
