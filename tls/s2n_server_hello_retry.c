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
#include "tls/extensions/s2n_cookie.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

/* From RFC5246 7.4.1.2. */
#define S2N_TLS_COMPRESSION_METHOD_NULL 0

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
const uint8_t hello_retry_req_random[S2N_TLS_RANDOM_DATA_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

/* Lets the server flag whether a HelloRetryRequest is needed while processing extensions */
int s2n_server_should_retry(struct s2n_connection *conn)
{
    S2N_ERROR_IF(conn->handshake.handshake_type & HELLO_RETRY_REQUEST, S2N_ERR_BAD_MESSAGE);

    conn->handshake.server_requires_hrr = 1;

    return 0;
}

/* Lets the server determine whether a HelloRetryRequest should be sent */
bool s2n_server_requires_retry(struct s2n_connection *conn)
{
    return conn->handshake.server_requires_hrr == 1;
}

/* Lets the client determine whether a HelloRetryRequest is valid */
bool s2n_server_hello_retry_is_valid(struct s2n_connection *conn)
{
    bool has_versions_ext = conn->server_protocol_version > 0;
    bool has_correct_random = (memcmp(hello_retry_req_random, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN) == 0);

    return has_versions_ext && has_correct_random && conn->client_protocol_version == S2N_TLS13;
}

int s2n_server_hello_retry_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    /* We only send retries in S2N_TLS13, so we know the legacy protocol version should be S2N_TLS12 */
    protocol_version[0] = (uint8_t)(S2N_TLS12 / 10);
    protocol_version[1] = (uint8_t)(S2N_TLS12 % 10);
    GUARD(s2n_stuffer_write_bytes(out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    /* Retry requests have a specifc random value */
    GUARD(s2n_stuffer_write_bytes(out, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN));

    /* Other values are set as a normal server hello */
    GUARD(s2n_stuffer_write_uint8(out, conn->session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, conn->session_id, conn->session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, conn->secure.cipher_suite->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
    GUARD(s2n_stuffer_write_uint8(out, S2N_TLS_COMPRESSION_METHOD_NULL));

    /* Write the extensions */
    GUARD(s2n_server_extensions_send(conn, out));

    /* The HelloRetryRandom was written to the stuffer, but also needs to be stored in the connection */
    memcpy_check(conn->secure.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);

    /* Clear all existing key shares so we can verify that what the client sends back is valid */
    GUARD(s2n_connection_clear_all_key_shares(conn));

    return 0;
}

int s2n_server_hello_retry_recv(struct s2n_connection *conn)
{
    /* Only allow one retry request per connection */
    S2N_ERROR_IF(conn->handshake.handshake_type & HELLO_RETRY_REQUEST, S2N_ERR_BAD_MESSAGE);

    /* The client extension parameters, like the key share extension, have already
     * been updated when the request was read off the wire. The state machine progress
     * will be updated after this message completes. Nothing else needs to be done here. */
    conn->handshake.hello_retry_request = 1;

    GUARD(s2n_conn_set_handshake_type(conn));

    return 0;
}
