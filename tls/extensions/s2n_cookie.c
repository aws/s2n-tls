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

#include "tls/extensions/s2n_cookie.h"
#include "tls/s2n_tls.h"

#define S2N_SIZE_OF_EXTENSION_TYPE          2
#define S2N_SIZE_OF_EXTENSION_DATA_SIZE     2
#define S2N_SIZE_OF_COOKIE_DATA_SIZE        2

const s2n_extension_type s2n_client_cookie_extension = {
    .iana_value = TLS_EXTENSION_COOKIE,
    .minimum_version = S2N_TLS13,
    .is_response = true,
    .send = s2n_extension_send_noop,
    .recv = s2n_extension_recv_noop,
    .should_send = s2n_extension_never_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_cookie_should_send(struct s2n_connection *conn);
static int s2n_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_server_cookie_extension = {
    .iana_value = TLS_EXTENSION_COOKIE,
    .minimum_version = S2N_TLS13,
    .is_response = false,
    .send = s2n_cookie_send,
    .recv = s2n_cookie_recv,
    .should_send = s2n_cookie_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_cookie_should_send(struct s2n_connection *conn)
{
    return conn && s2n_stuffer_data_available(&conn->cookie_stuffer) > 0;
}

static int s2n_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    uint16_t cookie_size = s2n_stuffer_data_available(&conn->cookie_stuffer);
    POSIX_GUARD(s2n_stuffer_write_uint16(out, cookie_size));
    POSIX_GUARD(s2n_stuffer_copy(&conn->cookie_stuffer, out, cookie_size));
    return S2N_SUCCESS;
}

static int s2n_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    POSIX_ENSURE_REF(conn);

    uint16_t cookie_len;
    POSIX_GUARD(s2n_stuffer_read_uint16(extension, &cookie_len));
    POSIX_ENSURE(s2n_stuffer_data_available(extension) == cookie_len, S2N_ERR_BAD_MESSAGE);

    POSIX_GUARD(s2n_stuffer_wipe(&conn->cookie_stuffer));
    POSIX_GUARD(s2n_stuffer_resize(&conn->cookie_stuffer, cookie_len));
    POSIX_GUARD(s2n_stuffer_copy(extension, &conn->cookie_stuffer, cookie_len));
    return S2N_SUCCESS;
}

/* Old-style extension functions -- remove after extensions refactor is complete */

int s2n_extensions_cookie_size(struct s2n_connection *conn)
{
    POSIX_GUARD(s2n_stuffer_reread(&conn->cookie_stuffer));

    if (s2n_stuffer_data_available(&conn->cookie_stuffer) == 0) {
        return 0;
    }

    const int cookie_extension_size = S2N_SIZE_OF_EXTENSION_TYPE
        + S2N_SIZE_OF_EXTENSION_DATA_SIZE
        + S2N_SIZE_OF_COOKIE_DATA_SIZE
        + s2n_stuffer_data_available(&conn->cookie_stuffer);

    return cookie_extension_size;
}

int s2n_extensions_cookie_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    return s2n_extension_send(&s2n_server_cookie_extension, conn, extension);
}

int s2n_extensions_cookie_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    return s2n_extension_send(&s2n_server_cookie_extension, conn, out);
}
