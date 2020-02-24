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

/* Determines whether a HelloRetryRequest is required to establish a connection */
bool s2n_server_requires_retry(struct s2n_connection *conn)
{
    return conn->handshake.requires_retry == 1;
}

/* Determines whether a HelloRetryRequest is valid */
bool s2n_server_hello_retry_is_valid(struct s2n_connection *conn)
{
    bool has_versions_ext = conn->server_protocol_version > 0;
    bool has_correct_random = s2n_constant_time_equals(hello_retry_req_random, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN);

    return has_versions_ext && has_correct_random;
}

static int s2n_save_clienthello1_cookie(struct s2n_connection *conn)
{
    /* Store the transcript in a cookie. This has to be done before the extensions are sent. */
    struct s2n_tls13_keys keys;
    GUARD(s2n_tls13_keys_from_conn(&keys, conn));

    /* Grab the current transcript hash to use as the ClientHello1 value.
     * This will be the Hash(ClientHello1) value in the cookie. */
    struct s2n_hash_state hash_state, client_hello1_hash;
    uint8_t hash_digest_length = keys.size;
    uint8_t client_hello1_digest_out[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));
    GUARD(s2n_hash_new(&client_hello1_hash));
    GUARD(s2n_hash_copy(&client_hello1_hash, &hash_state));
    GUARD(s2n_hash_digest(&client_hello1_hash, client_hello1_digest_out, hash_digest_length));
    GUARD(s2n_hash_free(&client_hello1_hash));

    /* Fill in the cookie stuffer so the hash will be sent out with the extensions */
    GUARD(s2n_stuffer_write_bytes(&conn->cookie_stuffer, client_hello1_digest_out, hash_digest_length));

    return 0;
}

/* Create the HelloRetryRequest message.
 * This function will be called when the retry is actually sent, and once
 * more when ClientHello2 is received and the transcript needs to be created.
 */
int s2n_server_hello_retry_write_message(uint8_t *session_id, uint8_t session_id_len, struct s2n_cipher_suite *cipher, struct s2n_stuffer *out)
{
    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    /* We only send retries in S2N_TLS13, so we know the legacy protocol version should be S2N_TLS12 */
    protocol_version[0] = (uint8_t)(S2N_TLS12 / 10);
    protocol_version[1] = (uint8_t)(S2N_TLS12 % 10);
    GUARD(s2n_stuffer_write_bytes(out, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));

    /* Retry requests have a specifc random value */
    GUARD(s2n_stuffer_write_bytes(out, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN));

    /* Other values are set as a normal server hello */
    GUARD(s2n_stuffer_write_uint8(out, session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, session_id, session_id_len));
    GUARD(s2n_stuffer_write_bytes(out, cipher->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
    GUARD(s2n_stuffer_write_uint8(out, S2N_TLS_COMPRESSION_METHOD_NULL));


    return 0;
}

int s2n_server_hello_retry_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    /* Save the ClientHello1 hash in the Cookie before the extensions are sent out */
    GUARD(s2n_save_clienthello1_cookie(conn));

    GUARD(s2n_server_hello_retry_write_message(conn->session_id,
        conn->session_id_len,
        conn->secure.cipher_suite,
        out));

    /* Write the extensions */
    GUARD(s2n_server_extensions_send(conn, out));

    /* The HelloRetryRandom was written to the stuffer, but also needs to be stored in the connection */
    memcpy_check(conn->secure.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);

    /* Wipe the cookie stuffer since we don't care about this anymore. The Client will echo
     * the value back to us, so we don't have to store any state. */
    GUARD(s2n_stuffer_reread(&conn->cookie_stuffer));

    /* Let the handshake writer know that we sent a request */
    conn->handshake.server_sent_hrr = 1;

    return 0;
}

int s2n_server_hello_retry_recv(struct s2n_connection *conn)
{
    /* Only allow one retry request per connection */
    S2N_ERROR_IF(conn->handshake.client_received_hrr == 1, S2N_ERR_BAD_MESSAGE);

    /* Verify this message meets the minimum requirements */
    S2N_ERROR_IF(!s2n_server_hello_retry_is_valid(conn), S2N_ERR_BAD_MESSAGE);

    return 0;
}
