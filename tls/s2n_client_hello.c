/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <stdlib.h>

#include "crypto/s2n_fips.h"

#include "error/s2n_errno.h"

#include "crypto/s2n_hash.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_tls_digest_preferences.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_bitmap.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

typedef char s2n_tls_extension_mask[8192];

static s2n_tls_extension_mask s2n_suported_extensions = { 0 };

void s2n_register_extension(uint16_t ext_type) {
    S2N_CBIT_SET(s2n_suported_extensions, ext_type);
}

struct s2n_client_hello *s2n_connection_get_client_hello(struct s2n_connection *conn) {
    if (conn->client_hello.parsed != 1) {
        return NULL;
    }

    return &conn->client_hello;
}

static uint32_t min_size(struct s2n_blob *blob, uint32_t max_length) {
    return blob->size < max_length ? blob->size : max_length;
}

ssize_t s2n_client_hello_get_raw_message_length(struct s2n_client_hello *ch) {
    notnull_check(ch);

    return ch->raw_message.blob.size;
}

ssize_t s2n_client_hello_get_raw_message(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    notnull_check(ch);
    notnull_check(out);

    uint32_t len = min_size(&ch->raw_message.blob, max_length);

    struct s2n_stuffer *raw_message = &ch->raw_message;
    GUARD(s2n_stuffer_reread(raw_message));
    GUARD(s2n_stuffer_read_bytes(raw_message, out, len));

    return len;
}

ssize_t s2n_client_hello_get_cipher_suites_length(struct s2n_client_hello *ch) {
    notnull_check(ch);

    return ch->cipher_suites.size;
}

ssize_t s2n_client_hello_get_cipher_suites(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    notnull_check(ch);
    notnull_check(out);
    notnull_check(ch->cipher_suites.data);

    uint32_t len = min_size(&ch->cipher_suites, max_length);

    memcpy_check(out, &ch->cipher_suites.data, len);

    return len;
}

ssize_t s2n_client_hello_get_extensions_length(struct s2n_client_hello *ch) {
    notnull_check(ch);

    return ch->extensions.size;
}

ssize_t s2n_client_hello_get_extensions(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    notnull_check(ch);
    notnull_check(out);
    notnull_check(ch->extensions.data);

    uint32_t len = min_size(&ch->extensions, max_length);

    memcpy_check(out, &ch->extensions.data, len);

    return len;
}

int s2n_client_hello_free(struct s2n_client_hello *client_hello)
{
    notnull_check(client_hello);

    GUARD(s2n_stuffer_free(&client_hello->raw_message));
    GUARD(s2n_client_hello_free_parsed_extensions(client_hello));

    /* These pointed to data in the raw_message stuffer,
       so we don't need to free them */
    client_hello->cipher_suites.data = NULL;
    client_hello->extensions.data = NULL;

    return 0;
}

int s2n_client_hello_free_parsed_extensions(struct s2n_client_hello *client_hello)
{
    notnull_check(client_hello);
    if (client_hello->parsed_extensions != NULL) {
        GUARD(s2n_array_free_p(&client_hello->parsed_extensions));
    }
    return 0;
}

int s2n_collect_client_hello(struct s2n_connection *conn, struct s2n_stuffer *source)
{
    notnull_check(conn);
    notnull_check(source);

    uint32_t size = s2n_stuffer_data_available(source);
    S2N_ERROR_IF(size == 0, S2N_ERR_BAD_MESSAGE);

    struct s2n_client_hello *ch = &conn->client_hello;

    GUARD(s2n_stuffer_resize(&ch->raw_message, size));
    GUARD(s2n_stuffer_copy(source, &ch->raw_message, size));

    return 0;
}

static int s2n_parse_client_hello(struct s2n_connection *conn)
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
    conn->client_hello_version = conn->client_protocol_version;
    /* Protocol version in the ClientHello is fixed at 0x0303(TLS 1.2) for
     * future versions of TLS. Still, we will negotiate down if a client sends
     * an unexpected value above 0x0303.
     */
    conn->actual_protocol_version = MIN(conn->client_protocol_version, conn->server_protocol_version);

    S2N_ERROR_IF(conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN || conn->session_id_len > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    GUARD(s2n_stuffer_read_bytes(in, conn->session_id, conn->session_id_len));

    uint16_t cipher_suites_length = 0;
    GUARD(s2n_stuffer_read_uint16(in, &cipher_suites_length));
    S2N_ERROR_IF(cipher_suites_length % S2N_TLS_CIPHER_SUITE_LEN, S2N_ERR_BAD_MESSAGE);

    client_hello->cipher_suites.size = cipher_suites_length;
    client_hello->cipher_suites.data = s2n_stuffer_raw_read(in, cipher_suites_length);
    notnull_check(client_hello->cipher_suites.data);
    /* Don't choose the cipher yet, read the extensions first */
    uint8_t num_compression_methods = 0;
    GUARD(s2n_stuffer_read_uint8(in, &num_compression_methods));
    GUARD(s2n_stuffer_skip_read(in, num_compression_methods));

    /* This is going to be our default if the client has no preference. */
    conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];

    uint16_t extensions_length = 0;
    if (s2n_stuffer_data_available(in) >= 2) {
        /* Read extensions if they are present */
        GUARD(s2n_stuffer_read_uint16(in, &extensions_length));

        S2N_ERROR_IF(extensions_length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

        client_hello->extensions.size = extensions_length;
        client_hello->extensions.data = s2n_stuffer_raw_read(in, extensions_length);
        notnull_check(client_hello->extensions.data);
    }

    return 0;
}

static int s2n_parsed_extensions_compare(const void *p, const void *q)
{
    const struct s2n_client_hello_parsed_extension *left = (const struct s2n_client_hello_parsed_extension *) p;
    const struct s2n_client_hello_parsed_extension *right = (const struct s2n_client_hello_parsed_extension *) q;

    return (int)left->extension_type - (int)right->extension_type;
}

static int s2n_populate_client_hello_extensions(struct s2n_client_hello *ch)
{
    if (ch->extensions.size == 0) {
        /* Client hello with no extensions, might be SSLv3, exit early */
        return 0;
    }

    if (ch->parsed_extensions == NULL) {
        notnull_check(ch->parsed_extensions = s2n_array_new(sizeof(struct s2n_client_hello_parsed_extension)));
    }

    struct s2n_stuffer in = {0};

    GUARD(s2n_stuffer_init(&in, &ch->extensions));
    GUARD(s2n_stuffer_write(&in, &ch->extensions));

    static __thread s2n_tls_extension_mask parsed_extensions_mask;
    memset(&parsed_extensions_mask, 0, sizeof(s2n_tls_extension_mask));

    while (s2n_stuffer_data_available(&in)) {
        uint16_t ext_size, ext_type;

        GUARD(s2n_stuffer_read_uint16(&in, &ext_type));
        GUARD(s2n_stuffer_read_uint16(&in, &ext_size));

        lte_check(ext_size, s2n_stuffer_data_available(&in));

        /* fail early if we encountered a duplicate extension */
        S2N_ERROR_IF(S2N_CBIT_TEST(parsed_extensions_mask, ext_type), S2N_ERR_BAD_MESSAGE);
        S2N_CBIT_SET(parsed_extensions_mask, ext_type);

        /* Skip invalid/unknown extensions */
        if (!S2N_CBIT_TEST(s2n_suported_extensions, ext_type)) {
            s2n_stuffer_skip_read(&in, ext_size);
            continue;
        }

        struct s2n_client_hello_parsed_extension *parsed_extension = s2n_array_pushback(ch->parsed_extensions);
        notnull_check(parsed_extension);

        parsed_extension->extension_type = ext_type;
        parsed_extension->extension.size = ext_size;

        parsed_extension->extension.data = s2n_stuffer_raw_read(&in, ext_size);
        notnull_check(parsed_extension->extension.data);
    }

    /* Sort extensions by extension type */
    qsort(ch->parsed_extensions->mem.data, ch->parsed_extensions->num_of_elements, ch->parsed_extensions->element_size, s2n_parsed_extensions_compare);

    return 0;
}
int s2n_handshake_status_handler(struct s2n_connection *conn)
{
    /* Set the handshake type */
    GUARD(s2n_conn_set_handshake_type(conn));

    if(conn->client_hello_version != S2N_SSLv2)
    {
        /* We've selected the parameters for the handshake, update the required hashes for this connection */
        GUARD(s2n_conn_update_required_handshake_hashes(conn));
    }

    return 0;
}
int s2n_process_client_hello(struct s2n_connection *conn)
{
    /* Client hello is parsed and config is finalized.
     * Negotiate protocol version, cipher suite, ALPN, select a cert, etc. */
    struct s2n_client_hello *client_hello = &conn->client_hello;

    if (client_hello->parsed_extensions != NULL && client_hello->parsed_extensions->num_of_elements > 0) {
        GUARD(s2n_client_extensions_recv(conn, client_hello->parsed_extensions));
    }

    const struct s2n_cipher_preferences *cipher_preferences;
    GUARD(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));

    if (conn->client_protocol_version < cipher_preferences->minimum_protocol_version) {
        GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        S2N_ERROR(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    }

    /* Find potential certificate matches before we choose the cipher. */
    GUARD(s2n_conn_find_name_matching_certs(conn));


    /* Now choose the ciphers and the cert chain. */
    GUARD(s2n_set_cipher_and_cert_as_tls_server(conn, client_hello->cipher_suites.data, client_hello->cipher_suites.size / 2));

    /* And set the signature and hash algorithm used for key exchange signatures */
    GUARD(s2n_choose_sig_scheme_from_peer_preference_list(conn, &conn->handshake_params.client_sig_hash_algs,
                                                           &conn->secure.conn_sig_scheme));

    return 0;
}

int s2n_client_hello_recv(struct s2n_connection *conn)
{
    /* Parse client hello */
    GUARD(s2n_parse_client_hello(conn));

    GUARD(s2n_populate_client_hello_extensions(&conn->client_hello));

    /* Mark the collected client hello as available when parsing is done and before the client hello callback */
    conn->client_hello.parsed = 1;

    /* Call client_hello_cb if exists, letting application to modify s2n_connection or swap s2n_config */
    if (conn->config->client_hello_cb) {
        int rc = conn->config->client_hello_cb(conn, conn->config->client_hello_cb_ctx);
        if (rc < 0) {
            GUARD(s2n_queue_reader_handshake_failure_alert(conn));
            S2N_ERROR(S2N_ERR_CANCELLED);
        }
        if (rc) {
            conn->server_name_used = 1;
        }
    }
    GUARD(s2n_process_client_hello(conn));
    return 0;
}

int s2n_client_hello_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_stuffer client_random = {0};
    struct s2n_blob b, r;
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    b.data = conn->secure.client_random;
    b.size = S2N_TLS_RANDOM_DATA_LEN;

    /* Create the client random data */
    GUARD(s2n_stuffer_init(&client_random, &b));

    r.data = s2n_stuffer_raw_write(&client_random, S2N_TLS_RANDOM_DATA_LEN);
    r.size = S2N_TLS_RANDOM_DATA_LEN;
    notnull_check(r.data);
    GUARD(s2n_get_public_random_data(&r));

    uint8_t reported_protocol_version = MIN(conn->client_protocol_version, S2N_TLS12);
    client_protocol_version[0] = reported_protocol_version / 10;
    client_protocol_version[1] = reported_protocol_version % 10;
    conn->client_hello_version = conn->client_protocol_version;

    GUARD(s2n_stuffer_write_bytes(out, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    GUARD(s2n_stuffer_copy(&client_random, out, S2N_TLS_RANDOM_DATA_LEN));

    /* Generate client session id when empty so that when server sends
     * an empty session id it is because it doesn't support session resumption
     */
    if (conn->session_id_len == 0 && conn->config->use_tickets) {
        struct s2n_blob session_id = { .data = conn->session_id, .size = S2N_TLS_SESSION_ID_MAX_LEN };

        GUARD(s2n_get_public_random_data(&session_id));
        conn->session_id_len = S2N_TLS_SESSION_ID_MAX_LEN;
    }

    GUARD(s2n_stuffer_write_uint8(out, conn->session_id_len));
    if (conn->session_id_len > 0) {
        GUARD(s2n_stuffer_write_bytes(out, conn->session_id, conn->session_id_len));
    }

    const struct s2n_cipher_preferences *cipher_preferences;
    GUARD(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));

    /* Find the number of available suites in the preference list. Some ciphers may be unavailable if s2n is built
     * with an older libcrypto
     */
    uint16_t num_available_suites = 0;
    for (int i = 0; i < cipher_preferences->count; i++) {
        if (cipher_preferences->suites[i]->available) {
            num_available_suites++;
        }
    }
    /* Include TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
    num_available_suites++;

    /* Write size of the list of available ciphers */
    GUARD(s2n_stuffer_write_uint16(out, num_available_suites * S2N_TLS_CIPHER_SUITE_LEN));

    /* Now, write the IANA values every available cipher suite in our list */
    for (int i = 0; i < cipher_preferences->count; i++ ) {
        if (cipher_preferences->suites[i]->available) {
            GUARD(s2n_stuffer_write_bytes(out, cipher_preferences->suites[i]->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
        }
    }
    /* Lastly, write TLS_EMPTY_RENEGOTIATION_INFO_SCSV so that server knows it's an initial handshake (RFC5746 Section 3.4) */
    uint8_t renegotiation_info_scsv[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_EMPTY_RENEGOTIATION_INFO_SCSV };
    GUARD(s2n_stuffer_write_bytes(out, renegotiation_info_scsv, S2N_TLS_CIPHER_SUITE_LEN));

    /* Zero compression methods */
    GUARD(s2n_stuffer_write_uint8(out, 1));
    GUARD(s2n_stuffer_write_uint8(out, 0));

    /* Write the extensions */
    GUARD(s2n_client_extensions_send(conn, out));

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

    const struct s2n_cipher_preferences *cipher_preferences;
    GUARD(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));

    if (conn->client_protocol_version < cipher_preferences->minimum_protocol_version) {
        GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        S2N_ERROR(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    }
    conn->actual_protocol_version = MIN(conn->client_protocol_version, conn->server_protocol_version);
    conn->client_hello_version = S2N_SSLv2;

    /* We start 5 bytes into the record */
    GUARD(s2n_stuffer_read_uint16(in, &cipher_suites_length));

    S2N_ERROR_IF(cipher_suites_length % S2N_SSLv2_CIPHER_SUITE_LEN, S2N_ERR_BAD_MESSAGE);

    GUARD(s2n_stuffer_read_uint16(in, &session_id_length));

    GUARD(s2n_stuffer_read_uint16(in, &challenge_length));

    S2N_ERROR_IF(challenge_length > S2N_TLS_RANDOM_DATA_LEN, S2N_ERR_BAD_MESSAGE);

    cipher_suites = s2n_stuffer_raw_read(in, cipher_suites_length);
    notnull_check(cipher_suites);

    /* Find potential certificate matches before we choose the cipher. */
    GUARD(s2n_conn_find_name_matching_certs(conn));

    GUARD(s2n_set_cipher_and_cert_as_sslv2_server(conn, cipher_suites, cipher_suites_length / S2N_SSLv2_CIPHER_SUITE_LEN));

    S2N_ERROR_IF(session_id_length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);
    if (session_id_length > 0 && session_id_length <= S2N_TLS_SESSION_ID_MAX_LEN) {
        GUARD(s2n_stuffer_read_bytes(in, conn->session_id, session_id_length));
        conn->session_id_len = (uint8_t) session_id_length;
    } else {
        GUARD(s2n_stuffer_skip_read(in, session_id_length));
    }

    struct s2n_blob b = {0};
    b.data = conn->secure.client_random;
    b.size = S2N_TLS_RANDOM_DATA_LEN;

    b.data += S2N_TLS_RANDOM_DATA_LEN - challenge_length;
    b.size -= S2N_TLS_RANDOM_DATA_LEN - challenge_length;

    GUARD(s2n_stuffer_read(in, &b));

    return 0;
}

int s2n_client_hello_get_parsed_extension(struct s2n_array *parsed_extensions, s2n_tls_extension_type extension_type,
        struct s2n_client_hello_parsed_extension *parsed_extension)
{
    notnull_check(parsed_extensions);

    struct s2n_client_hello_parsed_extension search = {0};
    search.extension_type = extension_type;

    struct s2n_client_hello_parsed_extension *result_extension = bsearch(&search, parsed_extensions->mem.data, parsed_extensions->num_of_elements,
            parsed_extensions->element_size, s2n_parsed_extensions_compare);

    notnull_check(result_extension);

    parsed_extension->extension_type = result_extension->extension_type;
    parsed_extension->extension = result_extension->extension;
    return 0;
}

ssize_t s2n_client_hello_get_extension_length(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type)
{
    notnull_check(ch);
    notnull_check(ch->parsed_extensions);

    struct s2n_client_hello_parsed_extension parsed_extension = {0};

    if (s2n_client_hello_get_parsed_extension(ch->parsed_extensions, extension_type, &parsed_extension)) {
        return 0;
    }

    return parsed_extension.extension.size;
}

ssize_t s2n_client_hello_get_extension_by_id(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type, uint8_t *out, uint32_t max_length)
{
    notnull_check(ch);
    notnull_check(out);
    notnull_check(ch->parsed_extensions);

    struct s2n_client_hello_parsed_extension parsed_extension = {0};

    if (s2n_client_hello_get_parsed_extension(ch->parsed_extensions, extension_type, &parsed_extension)) {
        return 0;
    }

    uint32_t len = min_size(&parsed_extension.extension, max_length);
    memcpy_check(out, parsed_extension.extension.data, len);
    return len;
}
