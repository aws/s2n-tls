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
#include "tls/s2n_client_hello.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

struct s2n_client_hello *s2n_connection_get_client_hello(struct s2n_connection *conn) {
    if (conn->client_hello.parsed != 1) {
        return NULL;
    }

    return &conn->client_hello;
}

static uint32_t min_size(struct s2n_blob *blob, uint32_t max_length) {
    return blob->size < max_length ? blob->size : max_length;
}

uint32_t s2n_client_hello_get_raw_message_length(struct s2n_client_hello *ch) {
    notnull_check(ch);

    return ch->raw_message.blob.size;
}

uint32_t s2n_client_hello_get_raw_message(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    notnull_check(ch);
    notnull_check(out);

    uint32_t len = min_size(&ch->raw_message.blob, max_length);

    struct s2n_stuffer *raw_message = &ch->raw_message;
    GUARD(s2n_stuffer_reread(raw_message));
    GUARD(s2n_stuffer_read_bytes(raw_message, out, len));

    return len;
}

uint32_t s2n_client_hello_get_cipher_suites_length(struct s2n_client_hello *ch) {
    notnull_check(ch);

    return ch->cipher_suites.size;
}

uint32_t s2n_client_hello_get_cipher_suites(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    notnull_check(ch);
    notnull_check(out);
    notnull_check(ch->cipher_suites.data);

    uint32_t len = min_size(&ch->cipher_suites, max_length);

    memcpy_check(out, &ch->cipher_suites.data, len);

    return len;
}

uint32_t s2n_client_hello_get_extensions_length(struct s2n_client_hello *ch) {
    notnull_check(ch);

    return ch->extensions.size;
}

uint32_t s2n_client_hello_get_extensions(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    notnull_check(ch);
    notnull_check(out);
    notnull_check(ch->extensions.data);

    uint32_t len = min_size(&ch->extensions, max_length);

    memcpy_check(out, &ch->extensions.data, len);

    return len;
}

int s2n_client_hello_free(struct s2n_client_hello *client_hello) {
    notnull_check(client_hello);

    GUARD(s2n_stuffer_free(&client_hello->raw_message));

    /* These pointed to data in the raw_message stuffer,
       so we don't need to free them */
    client_hello->cipher_suites.data = NULL;
    client_hello->extensions.data = NULL;

    return 0;
}

int s2n_collect_client_hello(struct s2n_connection *conn, struct s2n_stuffer *source)
{
    notnull_check(conn);
    notnull_check(source);

    uint32_t size = s2n_stuffer_data_available(source);
    if (size == 0) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    struct s2n_client_hello *ch = &conn->client_hello;

    GUARD(s2n_stuffer_resize(&ch->raw_message, size));
    GUARD(s2n_stuffer_copy(source, &ch->raw_message, size));

    return 0;
}

int s2n_client_hello_recv(struct s2n_connection *conn)
{
    GUARD(s2n_collect_client_hello(conn, &conn->handshake.io));

    /* Going forward, we parse the collected client hello */
    struct s2n_client_hello *client_hello = &conn->client_hello;
    struct s2n_stuffer *in = &client_hello->raw_message;

    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    GUARD(s2n_stuffer_read_bytes(in, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    GUARD(s2n_stuffer_erase_and_read_bytes(in, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
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

    uint16_t cipher_suites_length = 0;
    GUARD(s2n_stuffer_read_uint16(in, &cipher_suites_length));
    if (cipher_suites_length % S2N_TLS_CIPHER_SUITE_LEN) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    client_hello->cipher_suites.size = cipher_suites_length;
    client_hello->cipher_suites.data = s2n_stuffer_raw_read(in, cipher_suites_length);
    notnull_check(client_hello->cipher_suites.data);
    /* Don't choose the cipher yet, read the extensions first */

    uint8_t num_compression_methods = 0;
    GUARD(s2n_stuffer_read_uint8(in, &num_compression_methods));
    GUARD(s2n_stuffer_skip_read(in, num_compression_methods));

    /* This is going to be our default if the client has no preference. */
    conn->secure.server_ecc_params.negotiated_curve = &s2n_ecc_supported_curves[0];

    /* Default our signature digest algorithms */
    conn->secure.conn_hash_alg = S2N_HASH_MD5_SHA1;
    if (conn->actual_protocol_version == S2N_TLS12 || s2n_is_in_fips_mode()) {
        conn->secure.conn_hash_alg = S2N_HASH_SHA1;
    }

    uint16_t extensions_length = 0;
    if (s2n_stuffer_data_available(in) >= 2) {
        /* Read extensions if they are present */
        GUARD(s2n_stuffer_read_uint16(in, &extensions_length));

        if (extensions_length > s2n_stuffer_data_available(in)) {
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }

        client_hello->extensions.size = extensions_length;
        client_hello->extensions.data = s2n_stuffer_raw_read(in, extensions_length);
        notnull_check(client_hello->extensions.data);

        GUARD(s2n_client_extensions_recv(conn, &client_hello->extensions));
    }

    /* Mark the collected client hello as available when parsing over and before the client hello callback */
    client_hello->parsed = 1;

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
    GUARD(s2n_set_cipher_as_tls_server(conn, client_hello->cipher_suites.data, cipher_suites_length / 2));
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
