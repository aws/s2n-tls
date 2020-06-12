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
#include <stdbool.h>

#include "error/s2n_errno.h"
#include "utils/s2n_blob.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_server_extensions.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

/* From RFC5246 7.4.1.2. */
#define S2N_TLS_COMPRESSION_METHOD_NULL 0

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
uint8_t hello_retry_req_random[S2N_TLS_RANDOM_DATA_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

int s2n_hello_retry_validate(struct s2n_connection *conn)
{
    notnull_check(conn);

    ENSURE_POSIX(memcmp(hello_retry_req_random, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN) == 0,
                 S2N_ERR_INVALID_HELLO_RETRY);

    return S2N_SUCCESS;
}

static int s2n_conn_reset_retry_values(struct s2n_connection *conn)
{
    notnull_check(conn);

    /* Reset handshake values */
    conn->handshake.client_hello_received = 0;

    /* Reset client hello state */
    GUARD(s2n_stuffer_wipe(&conn->client_hello.raw_message));
    GUARD(s2n_stuffer_resize(&conn->client_hello.raw_message, 0));
    GUARD(s2n_client_hello_free(&conn->client_hello));
    GUARD(s2n_stuffer_growable_alloc(&conn->client_hello.raw_message, 0));

    return 0;
}

int s2n_server_hello_retry_send(struct s2n_connection *conn)
{
    notnull_check(conn);

    memcpy_check(conn->secure.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);

    GUARD(s2n_server_hello_write_message(conn));

    /* Write the extensions */
    GUARD(s2n_server_extensions_send(conn, &conn->handshake.io));

    /* Update transcript */
    GUARD(s2n_server_hello_retry_recreate_transcript(conn));
    GUARD(s2n_conn_reset_retry_values(conn));

    return 0;
}

int s2n_server_hello_retry_recv(struct s2n_connection *conn)
{
    notnull_check(conn);

    const struct s2n_ecc_named_curve *named_curve = conn->secure.server_ecc_evp_params.negotiated_curve;
    const struct s2n_ecc_preferences *ecc_pref = NULL;
    GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    notnull_check(ecc_pref);

    /* Upon receipt of the HelloRetryRequest, the client MUST verify that:
     * (1) the selected_group field corresponds to a group
     * which was provided in the "supported_groups" extension in the
     * original ClientHello and
     * (2) the selected_group field does not correspond to a group which was provided
     * in the "key_share" extension in the original ClientHello.
     * If either of these checks fails, then the client MUST abort the handshake.
     * */

    bool match = false;

    for (size_t i = 0; i < ecc_pref->count; i++) {
        if (ecc_pref->ecc_curves[i] == named_curve) {
            match = true;
            ENSURE_POSIX(conn->secure.client_ecc_evp_params[i].evp_pkey == NULL, S2N_ERR_INVALID_HELLO_RETRY);
            break;
        }
    }

    ENSURE_POSIX(match, S2N_ERR_INVALID_HELLO_RETRY);

    /* Update transcript hash */
    GUARD(s2n_server_hello_retry_recreate_transcript(conn));

    return S2N_SUCCESS;
}
