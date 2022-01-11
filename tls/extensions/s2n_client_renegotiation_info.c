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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_client_renegotiation_info.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_safety.h"

static int s2n_client_renegotiation_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_client_renegotiation_info_extension = {
    .iana_value = TLS_EXTENSION_RENEGOTIATION_INFO,
    .is_response = false,
    .send = s2n_extension_send_unimplemented,
    .recv = s2n_client_renegotiation_recv,
    .should_send = s2n_extension_never_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static int s2n_client_renegotiation_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /* RFC5746 Section 3.2: The renegotiated_connection field is of zero length for the initial handshake. */
    uint8_t renegotiated_connection_len;
    POSIX_GUARD(s2n_stuffer_read_uint8(extension, &renegotiated_connection_len));
    S2N_ERROR_IF(s2n_stuffer_data_available(extension) || renegotiated_connection_len, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

    conn->secure_renegotiation = 1;
    return S2N_SUCCESS;
}

/* Old-style extension functions -- remove after extensions refactor is complete */

int s2n_recv_client_renegotiation_info(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_client_renegotiation_info_extension, conn, extension);
}
