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

static int s2n_client_renegotiation_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_client_renegotiation_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);
static bool s2n_client_renegotiation_should_send(struct s2n_connection *conn);

const s2n_extension_type s2n_client_renegotiation_info_extension = {
    .iana_value = TLS_EXTENSION_RENEGOTIATION_INFO,
    .is_response = false,
    .send = s2n_client_renegotiation_send,
    .recv = s2n_client_renegotiation_recv,
    .should_send = s2n_client_renegotiation_should_send,

    /**
     *= https://tools.ietf.org/rfc/rfc5746#3.6
     *# o  If neither the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV nor the
     *#    "renegotiation_info" extension was included, set the
     *#    secure_renegotiation flag to FALSE.  In this case, some servers
     *#    may want to terminate the handshake instead of continuing
     *
     * The conn->secure_renegotiation flag defaults to false, so this is a no-op.
     * We do not terminate the handshake, although missing messaging for secure
     * renegotiation degrades client security.
     *
     * We could introduce an option to fail in this case in the future.
     */
    .if_missing = s2n_extension_noop_if_missing,
};

/**
 *= https://tools.ietf.org/rfc/rfc5746#3.5
 *# o  The client MUST include the "renegotiation_info" extension in the
 *#    ClientHello
 */
static bool s2n_client_renegotiation_should_send(struct s2n_connection *conn)
{
    return conn && s2n_handshake_is_renegotiation(conn);
}

/**
 *= https://tools.ietf.org/rfc/rfc5746#3.5
 *# o  The client MUST include the "renegotiation_info" extension in the
 *#    ClientHello, containing the saved client_verify_data.
 */
static int s2n_client_renegotiation_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);

    /**
     *= https://tools.ietf.org/rfc/rfc5746#3.5
     *# This text applies if the connection's "secure_renegotiation" flag is
     *# set to TRUE (if it is set to FALSE, see Section 4.2).
     */
    POSIX_ENSURE(conn->secure_renegotiation, S2N_ERR_NO_RENEGOTIATION);

    uint8_t renegotiated_connection_len = conn->handshake.finished_len;
    POSIX_GUARD(s2n_stuffer_write_uint8(out, renegotiated_connection_len));
    POSIX_GUARD(s2n_stuffer_write_bytes(out, conn->handshake.client_finished, renegotiated_connection_len));

    return S2N_SUCCESS;
}

/**
 *= https://tools.ietf.org/rfc/rfc5746#3.6
 *# o  The server MUST check if the "renegotiation_info" extension is
 *# included in the ClientHello.
 */
static int s2n_client_renegotiation_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    /**
     *= https://tools.ietf.org/rfc/rfc5746#3.6
     *# The server MUST then verify
     *# that the length of the "renegotiated_connection" field is zero,
     *# and if it is not, MUST abort the handshake.
     */
    uint8_t renegotiated_connection_len = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(extension, &renegotiated_connection_len));
    POSIX_ENSURE(s2n_stuffer_data_available(extension) == 0, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
    POSIX_ENSURE(renegotiated_connection_len == 0, S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);

    /**
     *= https://tools.ietf.org/rfc/rfc5746#3.6
     *# If the extension is present, set secure_renegotiation flag to TRUE.
     */
    conn->secure_renegotiation = 1;

    return S2N_SUCCESS;
}

/* Old-style extension functions -- remove after extensions refactor is complete */

int s2n_recv_client_renegotiation_info(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_client_renegotiation_info_extension, conn, extension);
}
