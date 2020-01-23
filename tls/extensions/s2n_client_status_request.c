/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_client_status_request.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_status_request_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_STATUS_REQUEST));
    GUARD(s2n_stuffer_write_uint16(out, 5));
    GUARD(s2n_stuffer_write_uint8(out, (uint8_t) conn->config->status_request_type));
    GUARD(s2n_stuffer_write_uint16(out, 0));
    GUARD(s2n_stuffer_write_uint16(out, 0));

    return 0;
}

int s2n_recv_client_status_request(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (s2n_stuffer_data_available(extension) < 5) {
        /* Malformed length, ignore the extension */
        return 0;
    }
    uint8_t type;
    GUARD(s2n_stuffer_read_uint8(extension, &type));
    if (type != (uint8_t) S2N_STATUS_REQUEST_OCSP) {
        /* We only support OCSP (type 1), ignore the extension */
        return 0;
    }
    conn->status_type = (s2n_status_request_type) type;
    return 0;
}
