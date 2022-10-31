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
#include "utils/s2n_safety.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_npn.h"
#include "tls/s2n_tls.h"

int s2n_tls12_encrypted_extensions_send(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE(conn->actual_protocol_version < S2N_TLS13, S2N_ERR_BAD_MESSAGE);

    struct s2n_stuffer *out = &conn->handshake.io;
    POSIX_GUARD(s2n_npn_encrypted_extension.send(conn, out));

    POSIX_GUARD_RESULT(s2n_crypto_parameters_switch(conn));

    return S2N_SUCCESS;
}

int s2n_tls12_encrypted_extensions_recv(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE(conn->actual_protocol_version < S2N_TLS13, S2N_ERR_BAD_MESSAGE);

    struct s2n_stuffer *in = &conn->handshake.io;
    POSIX_GUARD(s2n_npn_encrypted_extension.recv(conn, in));

    return S2N_SUCCESS;
}
