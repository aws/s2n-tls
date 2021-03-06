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

static bool s2n_renegotiation_info_should_send(struct s2n_connection *conn);
static int s2n_renegotiation_info_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_renegotiation_info_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_server_renegotiation_info_extension = {
    .iana_value = TLS_EXTENSION_RENEGOTIATION_INFO,
    .is_response = false,
    .send = s2n_renegotiation_info_send,
    .recv = s2n_renegotiation_info_recv,
    .should_send = s2n_renegotiation_info_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_renegotiation_info_should_send(struct s2n_connection *conn)
{
    return conn && conn->secure_renegotiation && s2n_connection_get_protocol_version(conn) < S2N_TLS13;
}

static int s2n_renegotiation_info_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    /* renegotiated_connection length. Zero since we don't support renegotiation. */
    POSIX_GUARD(s2n_stuffer_write_uint8(out, 0));
    return S2N_SUCCESS;
}

static int s2n_renegotiation_info_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /* RFC5746 Section 3.4: The client MUST then verify that the length of
     * the "renegotiated_connection" field is zero, and if it is not, MUST
     * abort the handshake. */
    uint8_t renegotiated_connection_len;
    POSIX_GUARD(s2n_stuffer_read_uint8(extension, &renegotiated_connection_len));
    S2N_ERROR_IF(s2n_stuffer_data_available(extension), S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
    S2N_ERROR_IF(renegotiated_connection_len, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

    POSIX_ENSURE_REF(conn);
    conn->secure_renegotiation = 1;
    return S2N_SUCCESS;
}

/* Old-style extension functions -- remove after extensions refactor is complete */

int s2n_recv_server_renegotiation_info_ext(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_server_renegotiation_info_extension, conn, extension);
}

int s2n_send_server_renegotiation_info_ext(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_extension_send(&s2n_server_renegotiation_info_extension, conn, out);
}

int s2n_server_renegotiation_info_ext_size(struct s2n_connection *conn)
{
    if (s2n_renegotiation_info_should_send(conn)) {
        /* 2 for ext type, 2 for extension length, 1 for value of 0 */
        return 5;
    }

    return 0;
}
