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

/* Target Functions: s2n_client_finished_recv */

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    /* Setup */
    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    POSIX_ENSURE_REF(server_conn);
    POSIX_GUARD(s2n_stuffer_write_bytes(&server_conn->handshake.io, buf, len));

    /* We do not use a GUARD macro here as there may not be enough bytes to write the necessary
     * amount, and the result of a failed read_bytes call is an acceptable test input. */
    s2n_stuffer_read_bytes(&server_conn->handshake.io, server_conn->handshake.client_finished, S2N_TLS_FINISHED_LEN);

    /* Run Test
     * Do not use GUARD macro here since the connection memory hasn't been freed.
     */
    s2n_client_finished_recv(server_conn);

    /* Cleanup */
    POSIX_GUARD(s2n_connection_free(server_conn));

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
