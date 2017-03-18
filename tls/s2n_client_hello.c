/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <time.h>
#include <stdint.h>

#include "crypto/s2n_fips.h"

#include "error/s2n_errno.h"

#include "crypto/s2n_hash.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

/* From RFC5246 A.4 */
#define S2N_TLS_CLIENT_HELLO    1

/* Per http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html C.2 
 */
#define S2N_SSL_CLIENT_HELLO    1

int s2n_client_hello_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint8_t compression_methods;
    uint16_t extensions_size;
    uint16_t cipher_suites_length;
    uint8_t *cipher_suites;
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    GUARD(s2n_stuffer_read_bytes(in, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    GUARD(s2n_stuffer_read_bytes(in, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_stuffer_read_uint8(in, &conn->session_id_len));

    conn->client_protocol_version = (client_protocol_version[0] * 10) + client_protocol_version[1];
    if (conn->client_protocol_version > conn->server_protocol_version) {
        GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    conn->client_hello_version = conn->client_protocol_version;
    conn->actual_protocol_version = MIN(conn->client_protocol_version, conn->server_protocol_version);

    if (conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN || conn->session_id_len > s2n_stuffer_data_available(in)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    GUARD(s2n_stuffer_read_bytes(in, conn->session_id, conn->session_id_len));

    GUARD(s2n_stuffer_read_uint16(in, &cipher_suites_length));
    if (cipher_suites_length % S2N_TLS_CIPHER_SUITE_LEN) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    cipher_suites = s2n_stuffer_raw_read(in, cipher_suites_length);
    notnull_check(cipher_suites);
    /* Don't choose the cipher yet, read the extensions first */

    GUARD(s2n_stuffer_read_uint8(in, &compression_methods));
    GUARD(s2n_stuffer_skip_read(in, compression_methods));

    /* This is going to be our default if the client has no preference. */
    conn->secure.server_ecc_params.negotiated_curve = &s2n_ecc_supported_curves[0];

    /* Default our signature digest algorithms */
    conn->secure.conn_hash_alg = S2N_HASH_MD5_SHA1;
    if (conn->actual_protocol_version == S2N_TLS12 || s2n_is_in_fips_mode()) {
        conn->secure.conn_hash_alg = S2N_HASH_SHA1;
    }

    if (s2n_stuffer_data_available(in) >= 2) {
        /* Read extensions if they are present */
        GUARD(s2n_stuffer_read_uint16(in, &extensions_size));

        if (extensions_size > s2n_stuffer_data_available(in)) {
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }

        struct s2n_blob extensions;
        extensions.size = extensions_size;
        extensions.data = s2n_stuffer_raw_read(in, extensions.size);
        notnull_check(extensions.data);

        GUARD(s2n_client_extensions_recv(conn, &extensions));
    }

    if (conn->config->client_hello_cb) {
        if (conn->config->client_hello_cb(conn, conn->config->client_hello_cb_ctx) < 0) {
            GUARD(s2n_queue_reader_handshake_failure_alert(conn));
            S2N_ERROR(S2N_ERR_CANCELLED);
        }
    }

    if (conn->client_protocol_version < conn->config->cipher_preferences->minimum_protocol_version) {
        GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    /* Now choose the ciphers and the cert chain. */
    GUARD(s2n_set_cipher_as_tls_server(conn, cipher_suites, cipher_suites_length / 2));
    conn->server->server_cert_chain = conn->config->cert_and_key_pairs;

    /* Set the handshake type */
    GUARD(s2n_conn_set_handshake_type(conn));

    /* We've selected the cipher, update the required hashes for this connection */
    GUARD(s2n_conn_update_required_handshake_hashes(conn));

    return 0;
}

int s2n_client_hello_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_stuffer client_random;
    struct s2n_blob b, r;
    uint8_t session_id_len = 0;
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    b.data = conn->secure.client_random;
    b.size = S2N_TLS_RANDOM_DATA_LEN;

    /* Create the client random data */
    GUARD(s2n_stuffer_init(&client_random, &b));

    r.data = s2n_stuffer_raw_write(&client_random, S2N_TLS_RANDOM_DATA_LEN);
    r.size = S2N_TLS_RANDOM_DATA_LEN;
    notnull_check(r.data);
    GUARD(s2n_get_public_random_data(&r));

    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;
    conn->client_hello_version = conn->client_protocol_version;

    GUARD(s2n_stuffer_write_bytes(out, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    GUARD(s2n_stuffer_copy(&client_random, out, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_stuffer_write_uint8(out, session_id_len));

    /* Find the number of available suites in the preference list. Some ciphers may be unavailable if s2n is built
     * with an older libcrypto
     */
    uint16_t num_available_suites = 0;
    for (int i = 0; i < conn->config->cipher_preferences->count; i++) {
        if (conn->config->cipher_preferences->suites[i]->available) {
            num_available_suites++;
        }
    }

    /* Write size of the list of available ciphers */
    GUARD(s2n_stuffer_write_uint16(out, num_available_suites * S2N_TLS_CIPHER_SUITE_LEN));

    /* Now, write the IANA values every available cipher suite in our list */
    for (int i = 0; i < conn->config->cipher_preferences->count; i++ ) {
        if (conn->config->cipher_preferences->suites[i]->available) {
            GUARD(s2n_stuffer_write_bytes(out, conn->config->cipher_preferences->suites[i]->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
        }
    }

    /* Zero compression methods */
    GUARD(s2n_stuffer_write_uint8(out, 1));
    GUARD(s2n_stuffer_write_uint8(out, 0));

    /* Write the extensions */
    GUARD(s2n_client_extensions_send(conn, out));

    /* Default our signature digest algorithm to SHA1. Will be used when verifying a client certificate. */
    conn->secure.conn_hash_alg = S2N_HASH_MD5_SHA1;
    if (conn->actual_protocol_version == S2N_TLS12 || s2n_is_in_fips_mode()) {
        conn->secure.conn_hash_alg = S2N_HASH_SHA1;
    }

    return 0;
}

/* See http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html 2.5 */
int s2n_sslv2_client_hello_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint16_t session_id_length;
    uint16_t cipher_suites_length;
    uint16_t challenge_length;
    uint8_t *cipher_suites;

    if (conn->client_protocol_version < conn->config->cipher_preferences->minimum_protocol_version || conn->client_protocol_version > conn->server_protocol_version) {
        GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    conn->actual_protocol_version = MIN(conn->client_protocol_version, conn->server_protocol_version);
    conn->client_hello_version = S2N_SSLv2;

    /* We start 5 bytes into the record */
    GUARD(s2n_stuffer_read_uint16(in, &cipher_suites_length));

    if (cipher_suites_length % S2N_SSLv2_CIPHER_SUITE_LEN) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    GUARD(s2n_stuffer_read_uint16(in, &session_id_length));

    GUARD(s2n_stuffer_read_uint16(in, &challenge_length));

    if (challenge_length > S2N_TLS_RANDOM_DATA_LEN) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    cipher_suites = s2n_stuffer_raw_read(in, cipher_suites_length);
    notnull_check(cipher_suites);
    GUARD(s2n_set_cipher_as_sslv2_server(conn, cipher_suites, cipher_suites_length / S2N_SSLv2_CIPHER_SUITE_LEN));

    if (session_id_length > s2n_stuffer_data_available(in)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    if (session_id_length > 0 && session_id_length <= S2N_TLS_SESSION_ID_MAX_LEN) {
        GUARD(s2n_stuffer_read_bytes(in, conn->session_id, session_id_length));
        conn->session_id_len = (uint8_t) session_id_length;
    } else {
        GUARD(s2n_stuffer_skip_read(in, session_id_length));
    }

    struct s2n_blob b;
    b.data = conn->secure.client_random;
    b.size = S2N_TLS_RANDOM_DATA_LEN;

    b.data += S2N_TLS_RANDOM_DATA_LEN - challenge_length;
    b.size -= S2N_TLS_RANDOM_DATA_LEN - challenge_length;

    GUARD(s2n_stuffer_read(in, &b));

    conn->server->server_cert_chain = conn->config->cert_and_key_pairs;
    GUARD(s2n_conn_set_handshake_type(conn));

    return 0;
}
