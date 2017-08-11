/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_resume.h"

int s2n_allowed_to_cache_connection(struct s2n_connection *conn)
{
    s2n_cert_auth_type client_cert_auth_type;
    GUARD(s2n_connection_get_client_auth_type(conn, &client_cert_auth_type));

    if(client_cert_auth_type != S2N_CERT_AUTH_NONE) {
        /* We're unable to cache connections with a Client Cert since we currently don't serialize the Client Cert,
         * which means that callers won't have access to the Client's Cert if the connection is resumed. */
        return 0;
    }

    struct s2n_config *config = conn->config;

    /* Caching is enabled iff all of the caching callbacks are set */
    return config->cache_store && config->cache_retrieve && config->cache_delete;
}

static int s2n_serialize_resumption_state(struct s2n_connection *conn, struct s2n_stuffer *to)
{
    uint64_t now;

    if (s2n_stuffer_space_remaining(to) < S2N_STATE_SIZE_IN_BYTES) {
        return -1;
    }

    /* Get the time */
    GUARD(conn->config->nanoseconds_since_epoch(conn->config->data_for_nanoseconds_since_epoch, &now));

    /* Write the entry */
    GUARD(s2n_stuffer_write_uint8(to, S2N_SERIALIZED_FORMAT_VERSION));
    GUARD(s2n_stuffer_write_uint8(to, conn->actual_protocol_version));
    GUARD(s2n_stuffer_write_bytes(to, conn->secure.cipher_suite->iana_value, S2N_TLS_CIPHER_SUITE_LEN));
    GUARD(s2n_stuffer_write_uint64(to, now));
    GUARD(s2n_stuffer_write_bytes(to, conn->secure.master_secret, S2N_TLS_SECRET_LEN));

    return 0;
}

static int s2n_deserialize_resumption_state(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    uint64_t now, then;
    uint8_t format;
    uint8_t protocol_version;
    uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN];

    if (s2n_stuffer_data_available(from) < S2N_STATE_SIZE_IN_BYTES) {
        return -1;
    }

    GUARD(s2n_stuffer_read_uint8(from, &format));
    if (format != S2N_SERIALIZED_FORMAT_VERSION) {
        return -1;
    }

    GUARD(s2n_stuffer_read_uint8(from, &protocol_version));
    if (protocol_version != conn->actual_protocol_version) {
        return -1;
    }

    GUARD(s2n_stuffer_read_bytes(from, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN));
    if (memcmp(conn->secure.cipher_suite->iana_value, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN)) {
        return -1;
    }

    GUARD(conn->config->nanoseconds_since_epoch(conn->config->data_for_nanoseconds_since_epoch, &now));

    GUARD(s2n_stuffer_read_uint64(from, &then));
    if (then > now) {
        return -1;
    }
    if (now - then > S2N_STATE_LIFETIME_IN_NANOS) {
        return -1;
    }

    /* Last but not least, put the master secret in place */
    GUARD(s2n_stuffer_read_bytes(from, conn->secure.master_secret, S2N_TLS_SECRET_LEN));

    return 0;
}

int s2n_resume_from_cache(struct s2n_connection *conn)
{
    uint8_t data[S2N_STATE_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob entry = {.data = data,.size = S2N_STATE_SIZE_IN_BYTES };
    struct s2n_stuffer from;
    uint64_t size;

    if (conn->session_id_len == 0 || conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN) {
        return -1;
    }

    GUARD(s2n_stuffer_init(&from, &entry));
    uint8_t *state = s2n_stuffer_raw_write(&from, entry.size);
    notnull_check(state);

    size = S2N_STATE_SIZE_IN_BYTES;
    if (conn->config->cache_retrieve(conn->config->cache_retrieve_data, conn->session_id, conn->session_id_len, state, &size)) {
        return -1;
    }

    if (size != S2N_STATE_SIZE_IN_BYTES) {
        return -1;
    }

    GUARD(s2n_deserialize_resumption_state(conn, &from));

    return 0;
}

int s2n_store_to_cache(struct s2n_connection *conn)
{
    uint8_t data[S2N_STATE_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob entry = {.data = data,.size = S2N_STATE_SIZE_IN_BYTES };
    struct s2n_stuffer to;

    if (!s2n_allowed_to_cache_connection(conn)) {
        return -1;
    }

    /* session_id_len should always be >0 since either the Client provided a SessionId or the Server generated a new
     * one for the Client */
    if (conn->session_id_len == 0 || conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN) {
        return -1;
    }

    GUARD(s2n_stuffer_init(&to, &entry));
    GUARD(s2n_serialize_resumption_state(conn, &to));

    /* Store to the cache */
    conn->config->cache_store(conn->config->cache_store_data, S2N_TLS_SESSION_CACHE_TTL, conn->session_id, conn->session_id_len, entry.data, entry.size);

    return 0;
}
