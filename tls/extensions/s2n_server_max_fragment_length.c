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

#include "tls/extensions/s2n_server_max_fragment_length.h"

static bool s2n_max_fragment_length_should_send(struct s2n_connection *conn);
static int s2n_max_fragment_length_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_max_fragment_length_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_server_max_fragment_length_extension = {
    .iana_value = TLS_EXTENSION_MAX_FRAG_LEN,
    .is_response = true,
    .send = s2n_max_fragment_length_send,
    .recv = s2n_max_fragment_length_recv,
    .should_send = s2n_max_fragment_length_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_max_fragment_length_should_send(struct s2n_connection *conn)
{
    return conn && conn->mfl_code != S2N_TLS_MAX_FRAG_LEN_EXT_NONE;
}

static int s2n_max_fragment_length_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_stuffer_write_uint8(out, conn->mfl_code));
    return S2N_SUCCESS;
}

static int s2n_max_fragment_length_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);

    uint8_t mfl_code;
    POSIX_GUARD(s2n_stuffer_read_uint8(extension, &mfl_code));
    S2N_ERROR_IF(mfl_code != conn->config->mfl_code, S2N_ERR_MAX_FRAG_LEN_MISMATCH);
    return S2N_SUCCESS;
}
