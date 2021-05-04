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

#include <sys/param.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

#include "crypto/s2n_fips.h"

#include "error/s2n_errno.h"

#include "crypto/s2n_hash.h"

#include "tls/extensions/s2n_extension_list.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_security_policies.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_bitmap.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

struct s2n_client_hello *s2n_connection_get_client_hello(struct s2n_connection *conn) {
    if (conn->client_hello.callback_invoked != 1) {
        return NULL;
    }

    return &conn->client_hello;
}

static uint32_t min_size(struct s2n_blob *blob, uint32_t max_length) {
    return blob->size < max_length ? blob->size : max_length;
}

static S2N_RESULT s2n_generate_client_session_id(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);

    /* Session id already generated - no-op */
    if (conn->session_id_len) {
        return S2N_RESULT_OK;
    }

    /* Only generate the session id for pre-TLS1.3 if using tickets */
    if (conn->client_protocol_version < S2N_TLS13 && !conn->config->use_tickets) {
        return S2N_RESULT_OK;
    }

    /* Generate the session id for TLS1.3 if in middlebox compatibility mode.
     * For now, we default to middlebox compatibility mode unless using QUIC. */
    if (conn->config->quic_enabled) {
        return S2N_RESULT_OK;
    }

    struct s2n_blob session_id = {0};
    RESULT_GUARD_POSIX(s2n_blob_init(&session_id, conn->session_id, S2N_TLS_SESSION_ID_MAX_LEN));
    RESULT_GUARD(s2n_get_public_random_data(&session_id));
    conn->session_id_len = S2N_TLS_SESSION_ID_MAX_LEN;

    return S2N_RESULT_OK;
}

ssize_t s2n_client_hello_get_raw_message_length(struct s2n_client_hello *ch) {
    POSIX_ENSURE_REF(ch);

    return ch->raw_message.blob.size;
}

ssize_t s2n_client_hello_get_raw_message(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    POSIX_ENSURE_REF(ch);
    POSIX_ENSURE_REF(out);

    uint32_t len = min_size(&ch->raw_message.blob, max_length);

    struct s2n_stuffer *raw_message = &ch->raw_message;
    POSIX_GUARD(s2n_stuffer_reread(raw_message));
    POSIX_GUARD(s2n_stuffer_read_bytes(raw_message, out, len));

    return len;
}

ssize_t s2n_client_hello_get_cipher_suites_length(struct s2n_client_hello *ch) {
    POSIX_ENSURE_REF(ch);

    return ch->cipher_suites.size;
}

int s2n_client_hello_cb_done(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE(conn->config->client_hello_cb_mode ==
        S2N_CLIENT_HELLO_CB_NONBLOCKING, S2N_ERR_INVALID_STATE);
    POSIX_ENSURE(conn->client_hello.callback_invoked == 1, S2N_ERR_ASYNC_NOT_PERFORMED);

    conn->client_hello.callback_async_blocked = 0;
    conn->client_hello.callback_async_done = 1;

    return S2N_SUCCESS;
}

ssize_t s2n_client_hello_get_cipher_suites(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    POSIX_ENSURE_REF(ch);
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(ch->cipher_suites.data);

    uint32_t len = min_size(&ch->cipher_suites, max_length);

    POSIX_CHECKED_MEMCPY(out, &ch->cipher_suites.data, len);

    return len;
}

ssize_t s2n_client_hello_get_extensions_length(struct s2n_client_hello *ch) {
    POSIX_ENSURE_REF(ch);

    return ch->extensions.raw.size;
}

ssize_t s2n_client_hello_get_extensions(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length)
{
    POSIX_ENSURE_REF(ch);
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(ch->extensions.raw.data);

    uint32_t len = min_size(&ch->extensions.raw, max_length);

    POSIX_CHECKED_MEMCPY(out, &ch->extensions.raw.data, len);

    return len;
}

int s2n_client_hello_free(struct s2n_client_hello *client_hello)
{
    POSIX_ENSURE_REF(client_hello);

    POSIX_GUARD(s2n_stuffer_free(&client_hello->raw_message));

    /* These point to data in the raw_message stuffer,
       so we don't need to free them */
    client_hello->cipher_suites.data = NULL;
    client_hello->extensions.raw.data = NULL;

    /* clean the CH nonblocking callback flags
     * incase we are preparing for CH retry */
    client_hello->callback_async_blocked = 0;
    client_hello->callback_async_done = 0;

    return 0;
}

int s2n_collect_client_hello(struct s2n_connection *conn, struct s2n_stuffer *source)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(source);

    uint32_t size = s2n_stuffer_data_available(source);
    S2N_ERROR_IF(size == 0, S2N_ERR_BAD_MESSAGE);

    struct s2n_client_hello *ch = &conn->client_hello;

    POSIX_GUARD(s2n_stuffer_resize(&ch->raw_message, size));
    POSIX_GUARD(s2n_stuffer_copy(source, &ch->raw_message, size));

    return 0;
}

static int s2n_parse_client_hello(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_collect_client_hello(conn, &conn->handshake.io));

    if (conn->client_hello_version == S2N_SSLv2) {
        POSIX_GUARD(s2n_sslv2_client_hello_recv(conn));
        return S2N_SUCCESS;
    }

    /* Going forward, we parse the collected client hello */
    struct s2n_client_hello *client_hello = &conn->client_hello;
    struct s2n_stuffer *in = &client_hello->raw_message;

    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];

    POSIX_GUARD(s2n_stuffer_read_bytes(in, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    POSIX_GUARD(s2n_stuffer_erase_and_read_bytes(in, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));

    /* Protocol version in the ClientHello is fixed at 0x0303(TLS 1.2) for
     * future versions of TLS. Therefore, we will negotiate down if a client sends
     * an unexpected value above 0x0303.
     */
    conn->client_protocol_version = MIN((client_protocol_version[0] * 10) + client_protocol_version[1], S2N_TLS12);
    conn->client_hello_version = conn->client_protocol_version;

    POSIX_GUARD(s2n_stuffer_read_uint8(in, &conn->session_id_len));
    S2N_ERROR_IF(conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN || conn->session_id_len > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    POSIX_GUARD(s2n_stuffer_read_bytes(in, conn->session_id, conn->session_id_len));

    uint16_t cipher_suites_length = 0;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &cipher_suites_length));
    POSIX_ENSURE(cipher_suites_length > 0, S2N_ERR_BAD_MESSAGE);
    POSIX_ENSURE(cipher_suites_length % S2N_TLS_CIPHER_SUITE_LEN == 0, S2N_ERR_BAD_MESSAGE);
   
    client_hello->cipher_suites.size = cipher_suites_length;
    client_hello->cipher_suites.data = s2n_stuffer_raw_read(in, cipher_suites_length);
    POSIX_ENSURE_REF(client_hello->cipher_suites.data);

    /* Don't choose the cipher yet, read the extensions first */
    uint8_t num_compression_methods = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(in, &num_compression_methods));
    POSIX_GUARD(s2n_stuffer_skip_read(in, num_compression_methods));

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);
    POSIX_ENSURE_GT(ecc_pref->count, 0);

    if (s2n_ecc_preferences_includes_curve(ecc_pref, TLS_EC_CURVE_SECP_256_R1)) {
        /* This is going to be our fallback if the client has no preference. */
        /* A TLS-compliant application MUST support key exchange with secp256r1 (NIST P-256) */
        /* and SHOULD support key exchange with X25519 [RFC7748]. */
        /* - https://tools.ietf.org/html/rfc8446#section-9.1 */
        conn->secure.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
    } else {
        /* P-256 is the preferred fallback option. These prefs don't support it, so choose whatever curve is first. */
        conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    }

    POSIX_GUARD(s2n_extension_list_parse(in, &conn->client_hello.extensions));

    return S2N_SUCCESS;
}

int s2n_process_client_hello(struct s2n_connection *conn)
{
    /* Client hello is parsed and config is finalized.
     * Negotiate protocol version, cipher suite, ALPN, select a cert, etc. */
    struct s2n_client_hello *client_hello = &conn->client_hello;

    const struct s2n_security_policy *security_policy;
    POSIX_GUARD(s2n_connection_get_security_policy(conn, &security_policy));

    /* Ensure that highest supported version is set correctly */
    if (!s2n_security_policy_supports_tls13(security_policy)) {
        conn->server_protocol_version = MIN(conn->server_protocol_version, S2N_TLS12);
        conn->actual_protocol_version = MIN(conn->server_protocol_version, S2N_TLS12);
    }

    /* s2n_extension_list_process clears the parsed extensions as it processes them.
     * To keep the version in client_hello intact for the extension retrieval APIs, process a copy instead.
     */
    s2n_parsed_extensions_list copy_of_parsed_extensions = conn->client_hello.extensions;
    POSIX_GUARD(s2n_extension_list_process(S2N_EXTENSION_LIST_CLIENT_HELLO, conn, &copy_of_parsed_extensions));

    /* After parsing extensions, select a curve and corresponding keyshare to use */
    if (conn->actual_protocol_version >= S2N_TLS13) {
        POSIX_GUARD(s2n_extensions_server_key_share_select(conn));
    }

    /* for pre TLS 1.3 connections, protocol selection is not done in supported_versions extensions, so do it here */
    if (conn->actual_protocol_version < S2N_TLS13) {
        conn->actual_protocol_version = MIN(conn->server_protocol_version, conn->client_protocol_version);
    }

    if (conn->client_protocol_version < security_policy->minimum_protocol_version) {
        POSIX_GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        POSIX_BAIL(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    }

    if (conn->config->quic_enabled) {
        POSIX_ENSURE(conn->actual_protocol_version >= S2N_TLS13, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    }

    /* Find potential certificate matches before we choose the cipher. */
    POSIX_GUARD(s2n_conn_find_name_matching_certs(conn));

    /* Now choose the ciphers we have certs for. */
    POSIX_GUARD(s2n_set_cipher_as_tls_server(conn, client_hello->cipher_suites.data, client_hello->cipher_suites.size / 2));

    /* If we're using a PSK, we don't need to choose a signature algorithm or certificate,
     * because no additional auth is required. */
    if (conn->psk_params.chosen_psk != NULL) {
        return S2N_SUCCESS;
    }

    /* And set the signature and hash algorithm used for key exchange signatures */
    POSIX_GUARD(s2n_choose_sig_scheme_from_peer_preference_list(conn,
        &conn->handshake_params.client_sig_hash_algs,
        &conn->secure.conn_sig_scheme));

    /* And finally, set the certs specified by the final auth + sig_alg combo. */
    POSIX_GUARD(s2n_select_certs_for_server_auth(conn, &conn->handshake_params.our_chain_and_key));

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_client_hello_process_cb_response(struct s2n_connection *conn, int rc)
{
    if (rc < 0) {
        goto fail;
    }
    switch(conn->config->client_hello_cb_mode) {
        case S2N_CLIENT_HELLO_CB_BLOCKING : {
            if(rc) {
                conn->server_name_used = 1;
            }
            return S2N_RESULT_OK;
        }
        case S2N_CLIENT_HELLO_CB_NONBLOCKING : {
            if (conn->client_hello.callback_async_done) {
                return S2N_RESULT_OK;
            }
            conn->client_hello.callback_async_blocked = 1;
            RESULT_BAIL(S2N_ERR_ASYNC_BLOCKED);
        }
    }
fail:
    /* rc < 0 */
    RESULT_GUARD_POSIX(s2n_queue_reader_handshake_failure_alert(conn));
    RESULT_BAIL(S2N_ERR_CANCELLED);
}

int s2n_client_hello_recv(struct s2n_connection *conn)
{
    POSIX_ENSURE(conn->client_hello.callback_async_blocked == 0, S2N_ERR_ASYNC_BLOCKED);

    if (conn->config->client_hello_cb_mode == S2N_CLIENT_HELLO_CB_BLOCKING ||
            !conn->client_hello.callback_async_done)
    {
        /* Parse client hello */
        POSIX_GUARD(s2n_parse_client_hello(conn));
    }
    /* If the CLIENT_HELLO has already been parsed, then we should not call
     * the client_hello_cb a second time. */
    if (conn->client_hello.callback_invoked == 0) {
        /* Mark the collected client hello as available when parsing is done and before the client hello callback */
        conn->client_hello.callback_invoked = 1;

        /* Call client_hello_cb if exists, letting application to modify s2n_connection or swap s2n_config */
        if (conn->config->client_hello_cb) {
            int rc = conn->config->client_hello_cb(conn, conn->config->client_hello_cb_ctx);
            POSIX_GUARD_RESULT(s2n_client_hello_process_cb_response(conn, rc));
        }
    }

    if (conn->client_hello_version != S2N_SSLv2) {
        POSIX_GUARD(s2n_process_client_hello(conn));
    }

    return 0;
}

int s2n_client_hello_send(struct s2n_connection *conn)
{
    const struct s2n_security_policy *security_policy;
    POSIX_GUARD(s2n_connection_get_security_policy(conn, &security_policy));

    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    POSIX_ENSURE_REF(cipher_preferences);

    /* Check whether cipher preference supports TLS 1.3. If it doesn't,
       our highest supported version is S2N_TLS12 */
    if (!s2n_security_policy_supports_tls13(security_policy)) {
        conn->client_protocol_version = MIN(conn->client_protocol_version, S2N_TLS12);
        conn->actual_protocol_version = MIN(conn->actual_protocol_version, S2N_TLS12);
    }

    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_stuffer client_random = {0};
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN] = {0};

    struct s2n_blob b = {0};
    POSIX_GUARD(s2n_blob_init(&b, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    /* Create the client random data */
    POSIX_GUARD(s2n_stuffer_init(&client_random, &b));

    struct s2n_blob r = {0};
    POSIX_GUARD(s2n_blob_init(&r, s2n_stuffer_raw_write(&client_random, S2N_TLS_RANDOM_DATA_LEN), S2N_TLS_RANDOM_DATA_LEN));
    POSIX_ENSURE_REF(r.data);
    POSIX_GUARD_RESULT(s2n_get_public_random_data(&r));

    uint8_t reported_protocol_version = MIN(conn->client_protocol_version, S2N_TLS12);
    client_protocol_version[0] = reported_protocol_version / 10;
    client_protocol_version[1] = reported_protocol_version % 10;
    conn->client_hello_version = reported_protocol_version;

    POSIX_GUARD(s2n_stuffer_write_bytes(out, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    POSIX_GUARD(s2n_stuffer_copy(&client_random, out, S2N_TLS_RANDOM_DATA_LEN));

    POSIX_GUARD_RESULT(s2n_generate_client_session_id(conn));
    POSIX_GUARD(s2n_stuffer_write_uint8(out, conn->session_id_len));
    if (conn->session_id_len > 0) {
        POSIX_GUARD(s2n_stuffer_write_bytes(out, conn->session_id, conn->session_id_len));
    }

    /* Reserve space for size of the list of available ciphers */
    struct s2n_stuffer_reservation available_cipher_suites_size;
    POSIX_GUARD(s2n_stuffer_reserve_uint16(out, &available_cipher_suites_size));

    /* Now, write the IANA values of every available cipher suite in our list */
    for (int i = 0; i < security_policy->cipher_preferences->count; i++ ) {
        if (cipher_preferences->suites[i]->available &&
                cipher_preferences->suites[i]->minimum_required_tls_version <= conn->client_protocol_version) {
            POSIX_GUARD(s2n_stuffer_write_bytes(out, security_policy->cipher_preferences->suites[i]->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
        }
    }

    /* Lastly, write TLS_EMPTY_RENEGOTIATION_INFO_SCSV so that server knows it's an initial handshake (RFC5746 Section 3.4) */
    uint8_t renegotiation_info_scsv[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_EMPTY_RENEGOTIATION_INFO_SCSV };
    POSIX_GUARD(s2n_stuffer_write_bytes(out, renegotiation_info_scsv, S2N_TLS_CIPHER_SUITE_LEN));

    /* Write size of the list of available ciphers */
    POSIX_GUARD(s2n_stuffer_write_vector_size(&available_cipher_suites_size));

    /* Zero compression methods */
    POSIX_GUARD(s2n_stuffer_write_uint8(out, 1));
    POSIX_GUARD(s2n_stuffer_write_uint8(out, 0));

    /* Write the extensions */
    POSIX_GUARD(s2n_extension_list_send(S2N_EXTENSION_LIST_CLIENT_HELLO, conn, out));

    /* Once the message is complete, finish calculating the PSK binders.
     *
     * The PSK binders require all the sizes in the ClientHello to be written correctly,
     * including the extension size and extension list size, and therefore have
     * to be calculated AFTER we finish writing the entire extension list. */
    POSIX_GUARD_RESULT(s2n_finish_psk_extension(conn));

    /* If early data was not requested as part of the ClientHello, it never will be. */
    if (conn->early_data_state == S2N_UNKNOWN_EARLY_DATA_STATE) {
        POSIX_GUARD_RESULT(s2n_connection_set_early_data_state(conn, S2N_EARLY_DATA_NOT_REQUESTED));
    }

    return S2N_SUCCESS;
}

/* See http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html 2.5 */
int s2n_sslv2_client_hello_recv(struct s2n_connection *conn)
{
    struct s2n_client_hello *client_hello = &conn->client_hello;
    struct s2n_stuffer *in = &client_hello->raw_message;

    const struct s2n_security_policy *security_policy;
    POSIX_GUARD(s2n_connection_get_security_policy(conn, &security_policy));

    if (conn->client_protocol_version < security_policy->minimum_protocol_version) {
        POSIX_GUARD(s2n_queue_reader_unsupported_protocol_version_alert(conn));
        POSIX_BAIL(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    }
    conn->actual_protocol_version = MIN(conn->client_protocol_version, conn->server_protocol_version);

    /* We start 5 bytes into the record */
    uint16_t cipher_suites_length;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &cipher_suites_length));
    POSIX_ENSURE(cipher_suites_length > 0, S2N_ERR_BAD_MESSAGE);
    POSIX_ENSURE(cipher_suites_length % S2N_SSLv2_CIPHER_SUITE_LEN == 0, S2N_ERR_BAD_MESSAGE);

    uint16_t session_id_length;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &session_id_length));

    uint16_t challenge_length;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &challenge_length));

    S2N_ERROR_IF(challenge_length > S2N_TLS_RANDOM_DATA_LEN, S2N_ERR_BAD_MESSAGE);

    client_hello->cipher_suites.size = cipher_suites_length;
    client_hello->cipher_suites.data = s2n_stuffer_raw_read(in, cipher_suites_length);
    POSIX_ENSURE_REF(client_hello->cipher_suites.data);

    /* Find potential certificate matches before we choose the cipher. */
    POSIX_GUARD(s2n_conn_find_name_matching_certs(conn));

    POSIX_GUARD(s2n_set_cipher_as_sslv2_server(conn, client_hello->cipher_suites.data, client_hello->cipher_suites.size / S2N_SSLv2_CIPHER_SUITE_LEN));
    POSIX_GUARD(s2n_choose_default_sig_scheme(conn, &conn->secure.conn_sig_scheme));
    POSIX_GUARD(s2n_select_certs_for_server_auth(conn, &conn->handshake_params.our_chain_and_key));

    S2N_ERROR_IF(session_id_length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);
    if (session_id_length > 0 && session_id_length <= S2N_TLS_SESSION_ID_MAX_LEN) {
        POSIX_GUARD(s2n_stuffer_read_bytes(in, conn->session_id, session_id_length));
        conn->session_id_len = (uint8_t) session_id_length;
    } else {
        POSIX_GUARD(s2n_stuffer_skip_read(in, session_id_length));
    }

    struct s2n_blob b = {0};
    POSIX_GUARD(s2n_blob_init(&b, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));

    b.data += S2N_TLS_RANDOM_DATA_LEN - challenge_length;
    b.size -= S2N_TLS_RANDOM_DATA_LEN - challenge_length;

    POSIX_GUARD(s2n_stuffer_read(in, &b));

    return 0;
}

static int s2n_client_hello_get_parsed_extension(s2n_tls_extension_type extension_type,
        s2n_parsed_extensions_list *parsed_extension_list, s2n_parsed_extension **parsed_extension)
{
    POSIX_ENSURE_REF(parsed_extension_list);
    POSIX_ENSURE_REF(parsed_extension);

    s2n_extension_type_id extension_type_id;
    POSIX_GUARD(s2n_extension_supported_iana_value_to_id(extension_type, &extension_type_id));

    s2n_parsed_extension *found_parsed_extension = &parsed_extension_list->parsed_extensions[extension_type_id];
    POSIX_ENSURE_REF(found_parsed_extension->extension.data);
    POSIX_ENSURE(found_parsed_extension->extension_type == extension_type, S2N_ERR_INVALID_PARSED_EXTENSIONS);

    *parsed_extension = found_parsed_extension;
    return S2N_SUCCESS;
}

ssize_t s2n_client_hello_get_extension_length(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type)
{
    POSIX_ENSURE_REF(ch);

    s2n_parsed_extension *parsed_extension = NULL;
    if (s2n_client_hello_get_parsed_extension(extension_type, &ch->extensions, &parsed_extension) != S2N_SUCCESS) {
        return 0;
    }

    return parsed_extension->extension.size;
}

ssize_t s2n_client_hello_get_extension_by_id(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type, uint8_t *out, uint32_t max_length)
{
    POSIX_ENSURE_REF(ch);
    POSIX_ENSURE_REF(out);

    s2n_parsed_extension *parsed_extension = NULL;
    if (s2n_client_hello_get_parsed_extension(extension_type, &ch->extensions, &parsed_extension) != S2N_SUCCESS) {
        return 0;
    }

    uint32_t len = min_size(&parsed_extension->extension, max_length);
    POSIX_CHECKED_MEMCPY(out, parsed_extension->extension.data, len);
    return len;
}
