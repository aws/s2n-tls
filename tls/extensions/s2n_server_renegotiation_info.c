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

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_server_renegotiation_info.h"

#define s2n_server_can_send_secure_renegotiation(conn) ((conn)->secure_renegotiation && \
        (conn)->actual_protocol_version < S2N_TLS13)

int s2n_recv_server_renegotiation_info_ext(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /* RFC5746 Section 3.4: The client MUST then verify that the length of
     * the "renegotiated_connection" field is zero, and if it is not, MUST
     * abort the handshake. */
    uint8_t renegotiated_connection_len;
    GUARD(s2n_stuffer_read_uint8(extension, &renegotiated_connection_len));
    S2N_ERROR_IF(s2n_stuffer_data_available(extension), S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
    S2N_ERROR_IF(renegotiated_connection_len, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

    conn->secure_renegotiation = 1;
    return 0;
}

int s2n_send_server_renegotiation_info_ext(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    if (s2n_server_can_send_secure_renegotiation(conn)) {
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_RENEGOTIATION_INFO));
        /* renegotiation_info length */
        GUARD(s2n_stuffer_write_uint16(out, 1));
        /* renegotiated_connection length. Zero since we don't support renegotiation. */
        GUARD(s2n_stuffer_write_uint8(out, 0));
    }

    return 0;
}

uint16_t s2n_server_renegotiation_info_ext_size(struct s2n_connection *conn)
{
    if (s2n_server_can_send_secure_renegotiation(conn)) {
        /* 2 for ext type, 2 for extension length, 1 for value of 0 */
        return 5;
    }

    return 0;
}
