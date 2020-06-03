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

#include "tls/extensions/s2n_server_alpn.h"

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

static bool s2n_alpn_should_send(struct s2n_connection *conn);
static int  s2n_alpn_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int  s2n_alpn_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_server_alpn_extension = {
    .iana_value  = TLS_EXTENSION_ALPN,
    .is_response = true,
    .send        = s2n_alpn_send,
    .recv        = s2n_alpn_recv,
    .should_send = s2n_alpn_should_send,
    .if_missing  = s2n_extension_noop_if_missing,
};

static bool s2n_alpn_should_send(struct s2n_connection *conn) { return conn && strlen(conn->application_protocol) > 0; }

static int s2n_alpn_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn);
    const uint8_t application_protocol_len = strlen(conn->application_protocol);

    /* Size of protocol name list */
    GUARD(s2n_stuffer_write_uint16(out, application_protocol_len + sizeof(uint8_t)));

    /* Single entry in protocol name list */
    GUARD(s2n_stuffer_write_uint8(out, application_protocol_len));
    GUARD(s2n_stuffer_write_bytes(out, ( uint8_t * )conn->application_protocol, application_protocol_len));

    return S2N_SUCCESS;
}

static int s2n_alpn_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    notnull_check(conn);

    uint16_t size_of_all;
    GUARD(s2n_stuffer_read_uint16(extension, &size_of_all));
    if (size_of_all > s2n_stuffer_data_available(extension) || size_of_all < 3) {
        /* ignore invalid extension size */
        return S2N_SUCCESS;
    }

    uint8_t protocol_len;
    GUARD(s2n_stuffer_read_uint8(extension, &protocol_len));
    lt_check(protocol_len, s2n_array_len(conn->application_protocol));

    uint8_t *protocol = s2n_stuffer_raw_read(extension, protocol_len);
    notnull_check(protocol);

    /* copy the first protocol name */
    memcpy_check(conn->application_protocol, protocol, protocol_len);
    conn->application_protocol[ protocol_len ] = '\0';

    return S2N_SUCCESS;
}

/* Old-style extension functions -- remove after extensions refactor is complete */

int s2n_server_extensions_alpn_send_size(struct s2n_connection *conn)
{
    const uint8_t application_protocol_len = strlen(conn->application_protocol);

    if (!application_protocol_len) { return 0; }

    return 3 * sizeof(uint16_t) + 1 * sizeof(uint8_t) + application_protocol_len;
}

int s2n_server_extensions_alpn_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_extension_send(&s2n_server_alpn_extension, conn, out);
}

int s2n_recv_server_alpn(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_recv(&s2n_server_alpn_extension, conn, extension);
}
