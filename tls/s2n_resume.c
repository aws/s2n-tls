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
#include <math.h>

#include <s2n.h>

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"
#include "utils/s2n_set.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_tls.h"

int s2n_allowed_to_cache_connection(struct s2n_connection *conn)
{
    /* We're unable to cache connections with a Client Cert since we currently don't serialize the Client Cert,
     * which means that callers won't have access to the Client's Cert if the connection is resumed. */
    if (s2n_connection_is_client_auth_enabled(conn) > 0) {
        return 0;
    }

    struct s2n_config *config = conn->config;

    notnull_check(config);
    return config->use_session_cache;
}

static int s2n_serialize_resumption_state(struct s2n_connection *conn, struct s2n_stuffer *to)
{
    uint64_t now;

    S2N_ERROR_IF(s2n_stuffer_space_remaining(to) < S2N_STATE_SIZE_IN_BYTES, S2N_ERR_STUFFER_IS_FULL);

    /* Get the time */
    GUARD(conn->config->wall_clock(conn->config->sys_clock_ctx, &now));

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
    uint8_t format;
    uint8_t protocol_version;
    uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN];

    S2N_ERROR_IF(s2n_stuffer_data_available(from) < S2N_STATE_SIZE_IN_BYTES, S2N_ERR_STUFFER_OUT_OF_DATA);

    GUARD(s2n_stuffer_read_uint8(from, &format));
    S2N_ERROR_IF(format != S2N_SERIALIZED_FORMAT_VERSION, S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);

    GUARD(s2n_stuffer_read_uint8(from, &protocol_version));
    S2N_ERROR_IF(protocol_version != conn->actual_protocol_version, S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);

    GUARD(s2n_stuffer_read_bytes(from, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN));
    S2N_ERROR_IF(memcmp(conn->secure.cipher_suite->iana_value, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN), S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);

    uint64_t now;
    GUARD(conn->config->wall_clock(conn->config->sys_clock_ctx, &now));

    uint64_t then;
    GUARD(s2n_stuffer_read_uint64(from, &then));
    S2N_ERROR_IF(then > now, S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);
    S2N_ERROR_IF(now - then > conn->config->session_state_lifetime_in_nanos, S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);

    /* Last but not least, put the master secret in place */
    GUARD(s2n_stuffer_read_bytes(from, conn->secure.master_secret, S2N_TLS_SECRET_LEN));

    return 0;
}

static int s2n_client_serialize_resumption_state(struct s2n_connection *conn, struct s2n_stuffer *to)
{
    /* Serialize session ticket */
   if (conn->config->use_tickets && conn->client_ticket.size > 0) {
       GUARD(s2n_stuffer_write_uint8(to, S2N_STATE_WITH_SESSION_TICKET));
       GUARD(s2n_stuffer_write_uint16(to, conn->client_ticket.size));
       GUARD(s2n_stuffer_write(to, &conn->client_ticket));
   } else {
       /* Serialize session id */
       GUARD(s2n_stuffer_write_uint8(to, S2N_STATE_WITH_SESSION_ID));
       GUARD(s2n_stuffer_write_uint8(to, conn->session_id_len));
       GUARD(s2n_stuffer_write_bytes(to, conn->session_id, conn->session_id_len));
   }

    /* Serialize session state */
    GUARD(s2n_serialize_resumption_state(conn, to));

    return 0;
}

static int s2n_client_deserialize_session_state(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    if (s2n_stuffer_data_available(from) < S2N_STATE_SIZE_IN_BYTES) {
        S2N_ERROR(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);
    }

    uint8_t format;
    uint64_t then;

    GUARD(s2n_stuffer_read_uint8(from, &format));
    if (format != S2N_SERIALIZED_FORMAT_VERSION) {
        S2N_ERROR(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);
    }

    GUARD(s2n_stuffer_read_uint8(from, &conn->actual_protocol_version));

    uint8_t *cipher_suite_wire = s2n_stuffer_raw_read(from, S2N_TLS_CIPHER_SUITE_LEN);
    notnull_check(cipher_suite_wire);
    GUARD(s2n_set_cipher_as_client(conn, cipher_suite_wire));

    GUARD(s2n_stuffer_read_uint64(from, &then));

    /* Last but not least, put the master secret in place */
    GUARD(s2n_stuffer_read_bytes(from, conn->secure.master_secret, S2N_TLS_SECRET_LEN));

    return 0;
}

static int s2n_client_deserialize_with_session_id(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    uint8_t session_id_len;
    GUARD(s2n_stuffer_read_uint8(from, &session_id_len));

    if (session_id_len == 0 || session_id_len > S2N_TLS_SESSION_ID_MAX_LEN
        || session_id_len > s2n_stuffer_data_available(from)) {
        S2N_ERROR(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);
    }

    conn->session_id_len = session_id_len;
    GUARD(s2n_stuffer_read_bytes(from, conn->session_id, session_id_len));

    GUARD(s2n_client_deserialize_session_state(conn, from));

    return 0;
}

static int s2n_client_deserialize_with_session_ticket(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    uint16_t session_ticket_len;
    GUARD(s2n_stuffer_read_uint16(from, &session_ticket_len));

    if (session_ticket_len == 0 || session_ticket_len > s2n_stuffer_data_available(from)) {
        S2N_ERROR(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);
    }

    GUARD(s2n_realloc(&conn->client_ticket, session_ticket_len));
    GUARD(s2n_stuffer_read(from, &conn->client_ticket));

    GUARD(s2n_client_deserialize_session_state(conn, from));

    return 0;
}

static int s2n_client_deserialize_resumption_state(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    uint8_t format;
    GUARD(s2n_stuffer_read_uint8(from, &format));

    switch (format) {
    case S2N_STATE_WITH_SESSION_ID:
        GUARD(s2n_client_deserialize_with_session_id(conn, from));
        break;
    case S2N_STATE_WITH_SESSION_TICKET:
        GUARD(s2n_client_deserialize_with_session_ticket(conn, from));
        break;
    default:
        S2N_ERROR(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);
    }

    return 0;
}

int s2n_resume_from_cache(struct s2n_connection *conn)
{
    S2N_ERROR_IF(conn->session_id_len == 0, S2N_ERR_SESSION_ID_TOO_SHORT);
    S2N_ERROR_IF(conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN, S2N_ERR_SESSION_ID_TOO_LONG);

    uint8_t data[S2N_TICKET_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob entry = {0};
    GUARD(s2n_blob_init(&entry, data, S2N_TICKET_SIZE_IN_BYTES));
    uint64_t size = entry.size;
    int result = conn->config->cache_retrieve(conn, conn->config->cache_retrieve_data, conn->session_id, conn->session_id_len, entry.data, &size);
    if (result == S2N_CALLBACK_BLOCKED) {
        S2N_ERROR(S2N_ERR_ASYNC_BLOCKED);
    }
    GUARD(result);

    S2N_ERROR_IF(size != entry.size, S2N_ERR_SIZE_MISMATCH);

    struct s2n_stuffer from = {0};
    GUARD(s2n_stuffer_init(&from, &entry));
    GUARD(s2n_stuffer_write(&from, &entry));
    GUARD(s2n_decrypt_session_cache(conn, &from));

    return 0;
}

int s2n_store_to_cache(struct s2n_connection *conn)
{
    uint8_t data[S2N_TICKET_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob entry = {0};
    GUARD(s2n_blob_init(&entry, data, S2N_TICKET_SIZE_IN_BYTES));
    struct s2n_stuffer to = {0};

    /* session_id_len should always be >0 since either the Client provided a SessionId or the Server generated a new
     * one for the Client */
    S2N_ERROR_IF(conn->session_id_len == 0, S2N_ERR_SESSION_ID_TOO_SHORT);
    S2N_ERROR_IF(conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN, S2N_ERR_SESSION_ID_TOO_LONG);

    GUARD(s2n_stuffer_init(&to, &entry));
    GUARD(s2n_encrypt_session_cache(conn, &to));

    /* Store to the cache */
    conn->config->cache_store(conn, conn->config->cache_store_data, S2N_TLS_SESSION_CACHE_TTL, conn->session_id, conn->session_id_len, entry.data, entry.size);

    return 0;
}

int s2n_connection_set_session(struct s2n_connection *conn, const uint8_t *session, size_t length)
{
    notnull_check(conn);
    notnull_check(session);

    DEFER_CLEANUP(struct s2n_blob session_data = {0}, s2n_free);
    GUARD(s2n_alloc(&session_data, length));
    memcpy(session_data.data, session, length);

    struct s2n_stuffer from = {0};
    GUARD(s2n_stuffer_init(&from, &session_data));
    GUARD(s2n_stuffer_write(&from, &session_data));
    GUARD(s2n_client_deserialize_resumption_state(conn, &from));
    return 0;
}

int s2n_connection_get_session(struct s2n_connection *conn, uint8_t *session, size_t max_length)
{
    notnull_check(conn);
    notnull_check(session);

    int len = s2n_connection_get_session_length(conn);

    if (len == 0) {
        return 0;
    }

    S2N_ERROR_IF(len > max_length, S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG);

    struct s2n_blob serialized_data = {0};
    GUARD(s2n_blob_init(&serialized_data, session, len));
    GUARD(s2n_blob_zero(&serialized_data));

    struct s2n_stuffer to = {0};
    GUARD(s2n_stuffer_init(&to, &serialized_data));
    GUARD(s2n_client_serialize_resumption_state(conn, &to));

    return len;
}

int s2n_connection_get_session_ticket_lifetime_hint(struct s2n_connection *conn)
{
    notnull_check(conn);
    S2N_ERROR_IF(!(conn->config->use_tickets && conn->client_ticket.size > 0), S2N_ERR_SESSION_TICKET_NOT_SUPPORTED);

    /* Session resumption using session ticket */
    return conn->ticket_lifetime_hint;
}

int s2n_connection_get_session_length(struct s2n_connection *conn)
{
    /* Session resumption using session ticket "format (1) + session_ticket_len + session_ticket + session state" */
    if (conn->config->use_tickets && conn->client_ticket.size > 0) {
        return S2N_STATE_FORMAT_LEN + S2N_SESSION_TICKET_SIZE_LEN + conn->client_ticket.size + S2N_STATE_SIZE_IN_BYTES;
    } else if (conn->session_id_len > 0) {
        /* Session resumption using session id: "format (0) + session_id_len + session_id + session state" */
        return S2N_STATE_FORMAT_LEN + 1 + conn->session_id_len + S2N_STATE_SIZE_IN_BYTES;
    } else {
        return 0;
    }
}

int s2n_connection_is_session_resumed(struct s2n_connection *conn)
{
    notnull_check(conn);
    return IS_RESUMPTION_HANDSHAKE(conn->handshake.handshake_type) ? 1 : 0;
}

int s2n_connection_is_ocsp_stapled(struct s2n_connection *conn)
{
    notnull_check(conn);

    if (conn->actual_protocol_version >= S2N_TLS13) {
        return (s2n_server_can_send_ocsp(conn) || s2n_server_sent_ocsp(conn));
    } else {
        return IS_OCSP_STAPLED(conn->handshake.handshake_type);
    }
}

int s2n_config_is_encrypt_decrypt_key_available(struct s2n_config *config)
{
    uint64_t now;
    struct s2n_ticket_key *ticket_key = NULL;
    GUARD(config->wall_clock(config->sys_clock_ctx, &now));
    notnull_check(config->ticket_keys);

    uint32_t ticket_keys_len = 0;
    GUARD_AS_POSIX(s2n_set_len(config->ticket_keys, &ticket_keys_len));

    for (uint32_t i = ticket_keys_len; i > 0; i--) {
        uint32_t idx = i - 1;
        GUARD_AS_POSIX(s2n_set_get(config->ticket_keys, idx, (void **)&ticket_key));
        uint64_t key_intro_time = ticket_key->intro_timestamp;

        if (key_intro_time < now
                && now < key_intro_time + config->encrypt_decrypt_key_lifetime_in_nanos) {
            return 1;
        }
    }

    return 0;
}

/* This function is used in s2n_get_ticket_encrypt_decrypt_key to compute the weight
 * of the keys and to choose a single key from all of the encrypt-decrypt keys.
 * Higher the weight of the key, higher the probability of being picked.
 */
int s2n_compute_weight_of_encrypt_decrypt_keys(struct s2n_config *config,
                                               uint8_t *encrypt_decrypt_keys_index,
                                               uint8_t num_encrypt_decrypt_keys,
                                               uint64_t now)
{
    double total_weight = 0;
    struct s2n_ticket_key_weight ticket_keys_weight[S2N_MAX_TICKET_KEYS];
    struct s2n_ticket_key *ticket_key = NULL;

    /* Compute weight of encrypt-decrypt keys */
    for (int i = 0; i < num_encrypt_decrypt_keys; i++) {
        GUARD_AS_POSIX(s2n_set_get(config->ticket_keys, encrypt_decrypt_keys_index[i], (void **)&ticket_key));

        uint64_t key_intro_time = ticket_key->intro_timestamp;
        uint64_t key_encryption_peak_time = key_intro_time + (config->encrypt_decrypt_key_lifetime_in_nanos / 2);

        /* The % of encryption using this key is linearly increasing */
        if (now < key_encryption_peak_time) {
            ticket_keys_weight[i].key_weight = now - key_intro_time;
        } else {
            /* The % of encryption using this key is linearly decreasing */
            ticket_keys_weight[i].key_weight = (config->encrypt_decrypt_key_lifetime_in_nanos / 2) - (now - key_encryption_peak_time);
        }

        ticket_keys_weight[i].key_index = encrypt_decrypt_keys_index[i];
        total_weight += ticket_keys_weight[i].key_weight;
    }

    /* Pick a random number in [0, 1). Using 53 bits (IEEE 754 double-precision floats). */
    uint64_t random_int = 0;
    GUARD_AS_POSIX(s2n_public_random(pow(2, 53), &random_int));
    double random = (double)random_int / (double)pow(2, 53);

    /* Compute cumulative weight of encrypt-decrypt keys */
    for (int i = 0; i < num_encrypt_decrypt_keys; i++) {
        ticket_keys_weight[i].key_weight = ticket_keys_weight[i].key_weight / total_weight;

        if (i > 0) {
            ticket_keys_weight[i].key_weight += ticket_keys_weight[i - 1].key_weight;
        }

        if (ticket_keys_weight[i].key_weight > random) {
            return ticket_keys_weight[i].key_index;
        }
    }

    S2N_ERROR(S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED);
}

/* This function is used in s2n_encrypt_session_ticket in order for s2n to
 * choose a key in encrypt-decrypt state from all of the keys added to config
 */
struct s2n_ticket_key *s2n_get_ticket_encrypt_decrypt_key(struct s2n_config *config)
{
    uint8_t num_encrypt_decrypt_keys = 0;
    uint8_t encrypt_decrypt_keys_index[S2N_MAX_TICKET_KEYS];
    struct s2n_ticket_key *ticket_key = NULL;

    uint64_t now;
    GUARD_PTR(config->wall_clock(config->sys_clock_ctx, &now));
    notnull_check_ptr(config->ticket_keys);

    uint32_t ticket_keys_len = 0;
    GUARD_RESULT_PTR(s2n_set_len(config->ticket_keys, &ticket_keys_len));

    for (uint32_t i = ticket_keys_len; i > 0; i--) {
        uint32_t idx = i - 1;
        GUARD_RESULT_PTR(s2n_set_get(config->ticket_keys, idx, (void **)&ticket_key));
        uint64_t key_intro_time = ticket_key->intro_timestamp;

        if (key_intro_time < now
                && now < key_intro_time + config->encrypt_decrypt_key_lifetime_in_nanos) {
            encrypt_decrypt_keys_index[num_encrypt_decrypt_keys] = idx;
            num_encrypt_decrypt_keys++;
        }
    }

    if (num_encrypt_decrypt_keys == 0) {
        S2N_ERROR_PTR(S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY);
    }

    if (num_encrypt_decrypt_keys == 1) {
        GUARD_RESULT_PTR(s2n_set_get(config->ticket_keys, encrypt_decrypt_keys_index[0], (void **)&ticket_key));
        return ticket_key;
    }

    int8_t idx;
    GUARD_PTR(idx = s2n_compute_weight_of_encrypt_decrypt_keys(config, encrypt_decrypt_keys_index, num_encrypt_decrypt_keys, now));

    GUARD_RESULT_PTR(s2n_set_get(config->ticket_keys, idx, (void **)&ticket_key));
    return ticket_key;
}

/* This function is used in s2n_decrypt_session_ticket in order for s2n to
 * find the matching key that was used for encryption.
 */
struct s2n_ticket_key *s2n_find_ticket_key(struct s2n_config *config, const uint8_t *name)
{
    uint64_t now;
    struct s2n_ticket_key *ticket_key = NULL;
    GUARD_PTR(config->wall_clock(config->sys_clock_ctx, &now));
    notnull_check_ptr(config->ticket_keys);

    uint32_t ticket_keys_len = 0;
    GUARD_RESULT_PTR(s2n_set_len(config->ticket_keys, &ticket_keys_len));

    for (uint32_t i = 0; i < ticket_keys_len; i++) {
        GUARD_RESULT_PTR(s2n_set_get(config->ticket_keys, i, (void **)&ticket_key));

        if (memcmp(ticket_key->key_name, name, S2N_TICKET_KEY_NAME_LEN) == 0) {

            /* Check to see if the key has expired */
            if (now >= ticket_key->intro_timestamp +
                                config->encrypt_decrypt_key_lifetime_in_nanos + config->decrypt_key_lifetime_in_nanos) {
                s2n_config_wipe_expired_ticket_crypto_keys(config, i);

                return NULL;
            }

            return ticket_key;
        }
    }

    return NULL;
}

int s2n_encrypt_session_ticket(struct s2n_connection *conn, struct s2n_stuffer *to)
{
    struct s2n_ticket_key *key;
    struct s2n_session_key aes_ticket_key = {0};
    struct s2n_blob aes_key_blob = {0};

    uint8_t iv_data[S2N_TLS_GCM_IV_LEN] = { 0 };
    struct s2n_blob iv = {0};
    GUARD(s2n_blob_init(&iv, iv_data, sizeof(iv_data)));

    uint8_t aad_data[S2N_TICKET_AAD_LEN] = { 0 };
    struct s2n_blob aad_blob = {0};
    GUARD(s2n_blob_init(&aad_blob, aad_data, sizeof(aad_data)));
    struct s2n_stuffer aad = {0};

    uint8_t s_data[S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = { 0 };
    struct s2n_blob state_blob = {0};
    GUARD(s2n_blob_init(&state_blob, s_data, sizeof(s_data)));
    struct s2n_stuffer state = {0};

    key = s2n_get_ticket_encrypt_decrypt_key(conn->config);

    /* No keys loaded by the user or the keys are either in decrypt-only or expired state */
    S2N_ERROR_IF(!key, S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY);

    GUARD(s2n_stuffer_write_bytes(to, key->key_name, S2N_TICKET_KEY_NAME_LEN));

    GUARD_AS_POSIX(s2n_get_public_random_data(&iv));
    GUARD(s2n_stuffer_write(to, &iv));

    GUARD(s2n_blob_init(&aes_key_blob, key->aes_key, S2N_AES256_KEY_LEN));
    GUARD(s2n_session_key_alloc(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.init(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.set_encryption_key(&aes_ticket_key, &aes_key_blob));

    GUARD(s2n_stuffer_init(&aad, &aad_blob));
    GUARD(s2n_stuffer_write_bytes(&aad, key->implicit_aad, S2N_TICKET_AAD_IMPLICIT_LEN));
    GUARD(s2n_stuffer_write_bytes(&aad, key->key_name, S2N_TICKET_KEY_NAME_LEN));

    GUARD(s2n_stuffer_init(&state, &state_blob));
    GUARD(s2n_serialize_resumption_state(conn, &state));

    GUARD(s2n_aes256_gcm.io.aead.encrypt(&aes_ticket_key, &iv, &aad_blob, &state_blob, &state_blob));

    GUARD(s2n_stuffer_write(to, &state_blob));

    GUARD(s2n_aes256_gcm.destroy_key(&aes_ticket_key));
    GUARD(s2n_session_key_free(&aes_ticket_key));

    return 0;
}

int s2n_decrypt_session_ticket(struct s2n_connection *conn)
{
    struct s2n_ticket_key *key;
    struct s2n_session_key aes_ticket_key = {0};
    struct s2n_blob aes_key_blob = {0};
    struct s2n_stuffer *from;

    uint8_t key_name[S2N_TICKET_KEY_NAME_LEN];

    uint8_t iv_data[S2N_TLS_GCM_IV_LEN] = { 0 };
    struct s2n_blob iv = { 0 };
    GUARD(s2n_blob_init(&iv, iv_data, sizeof(iv_data)));

    uint8_t aad_data[S2N_TICKET_AAD_LEN] = { 0 };
    struct s2n_blob aad_blob = {0};
    GUARD(s2n_blob_init(&aad_blob, aad_data, sizeof(aad_data)));
    struct s2n_stuffer aad = {0};

    uint8_t s_data[S2N_STATE_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob state_blob = {0};
    GUARD(s2n_blob_init(&state_blob, s_data, sizeof(s_data)));
    struct s2n_stuffer state = {0};

    uint8_t en_data[S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = {0};
    struct s2n_blob en_blob = {0};
    GUARD(s2n_blob_init(&en_blob, en_data, sizeof(en_data)));

    from = &conn->client_ticket_to_decrypt;
    GUARD(s2n_stuffer_read_bytes(from, key_name, S2N_TICKET_KEY_NAME_LEN));

    key = s2n_find_ticket_key(conn->config, key_name);

    /* Key has expired; do full handshake with New Session Ticket (NST) */
    S2N_ERROR_IF(!key, S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND);

    GUARD(s2n_stuffer_read(from, &iv));

    s2n_blob_init(&aes_key_blob, key->aes_key, S2N_AES256_KEY_LEN);
    GUARD(s2n_session_key_alloc(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.init(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.set_decryption_key(&aes_ticket_key, &aes_key_blob));

    GUARD(s2n_stuffer_init(&aad, &aad_blob));
    GUARD(s2n_stuffer_write_bytes(&aad, key->implicit_aad, S2N_TICKET_AAD_IMPLICIT_LEN));
    GUARD(s2n_stuffer_write_bytes(&aad, key->key_name, S2N_TICKET_KEY_NAME_LEN));

    GUARD(s2n_stuffer_read(from, &en_blob));

    GUARD(s2n_aes256_gcm.io.aead.decrypt(&aes_ticket_key, &iv, &aad_blob, &en_blob, &en_blob));

    GUARD(s2n_stuffer_init(&state, &state_blob));
    GUARD(s2n_stuffer_write_bytes(&state, en_data, S2N_STATE_SIZE_IN_BYTES));

    GUARD(s2n_deserialize_resumption_state(conn, &state));

    GUARD(s2n_aes256_gcm.destroy_key(&aes_ticket_key));
    GUARD(s2n_session_key_free(&aes_ticket_key));

    uint64_t now;
    GUARD(conn->config->wall_clock(conn->config->sys_clock_ctx, &now));

    /* If the key is in decrypt-only state, then a new key is assigned
     * for the ticket.
     */
    if (now >= key->intro_timestamp + conn->config->encrypt_decrypt_key_lifetime_in_nanos) {
        /* Check if a key in encrypt-decrypt state is available */
        if (s2n_config_is_encrypt_decrypt_key_available(conn->config) == 1) {
            conn->session_ticket_status = S2N_NEW_TICKET;
            conn->handshake.handshake_type |= WITH_SESSION_TICKET;

            return 0;
        }
    }

    return 0;
}

int s2n_encrypt_session_cache(struct s2n_connection *conn, struct s2n_stuffer *to)
{
    return s2n_encrypt_session_ticket(conn, to);
}


int s2n_decrypt_session_cache(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    struct s2n_ticket_key *key;
    struct s2n_session_key aes_ticket_key = {0};
    struct s2n_blob aes_key_blob = {0};

    uint8_t key_name[S2N_TICKET_KEY_NAME_LEN] = {0};

    uint8_t iv_data[S2N_TLS_GCM_IV_LEN] = { 0 };
    struct s2n_blob iv = {0};
    GUARD(s2n_blob_init(&iv, iv_data, sizeof(iv_data)));

    uint8_t aad_data[S2N_TICKET_AAD_LEN] = { 0 };
    struct s2n_blob aad_blob = {0};
    GUARD(s2n_blob_init(&aad_blob, aad_data, sizeof(aad_data)));
    struct s2n_stuffer aad = {0};

    uint8_t s_data[S2N_STATE_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob state_blob = {0};
    GUARD(s2n_blob_init(&state_blob, s_data, sizeof(s_data)));
    struct s2n_stuffer state = {0};

    uint8_t en_data[S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN] = {0};
    struct s2n_blob en_blob = {0};
    GUARD(s2n_blob_init(&en_blob, en_data, sizeof(en_data)));

    GUARD(s2n_stuffer_read_bytes(from, key_name, S2N_TICKET_KEY_NAME_LEN));

    key = s2n_find_ticket_key(conn->config, key_name);

    /* Key has expired; do full handshake with New Session Ticket (NST) */
    S2N_ERROR_IF(!key, S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND);

    GUARD(s2n_stuffer_read(from, &iv));

    s2n_blob_init(&aes_key_blob, key->aes_key, S2N_AES256_KEY_LEN);
    GUARD(s2n_session_key_alloc(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.init(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.set_decryption_key(&aes_ticket_key, &aes_key_blob));

    GUARD(s2n_stuffer_init(&aad, &aad_blob));
    GUARD(s2n_stuffer_write_bytes(&aad, key->implicit_aad, S2N_TICKET_AAD_IMPLICIT_LEN));
    GUARD(s2n_stuffer_write_bytes(&aad, key->key_name, S2N_TICKET_KEY_NAME_LEN));

    GUARD(s2n_stuffer_read(from, &en_blob));

    GUARD(s2n_aes256_gcm.io.aead.decrypt(&aes_ticket_key, &iv, &aad_blob, &en_blob, &en_blob));

    GUARD(s2n_stuffer_init(&state, &state_blob));
    GUARD(s2n_stuffer_write_bytes(&state, en_data, S2N_STATE_SIZE_IN_BYTES));

    GUARD(s2n_deserialize_resumption_state(conn, &state));

    GUARD(s2n_aes256_gcm.destroy_key(&aes_ticket_key));
    GUARD(s2n_session_key_free(&aes_ticket_key));

    return 0;
}

/* This function is used to remove all or just one expired key from server config */
int s2n_config_wipe_expired_ticket_crypto_keys(struct s2n_config *config, int8_t expired_key_index)
{
    int num_of_expired_keys = 0;
    int expired_keys_index[S2N_MAX_TICKET_KEYS];
    struct s2n_ticket_key *ticket_key = NULL;

    if (expired_key_index != -1) {
        expired_keys_index[num_of_expired_keys] = expired_key_index;
        num_of_expired_keys++;

        goto end;
    }

    uint64_t now;
    GUARD(config->wall_clock(config->sys_clock_ctx, &now));
    notnull_check(config->ticket_keys);

    uint32_t ticket_keys_len = 0;
    GUARD_AS_POSIX(s2n_set_len(config->ticket_keys, &ticket_keys_len));

    for (uint32_t i = 0; i < ticket_keys_len; i++) {
        GUARD_AS_POSIX(s2n_set_get(config->ticket_keys, i, (void **)&ticket_key));
        if (now >= ticket_key->intro_timestamp +
                   config->encrypt_decrypt_key_lifetime_in_nanos + config->decrypt_key_lifetime_in_nanos) {
            expired_keys_index[num_of_expired_keys] = i;
            num_of_expired_keys++;
        }
    }

end:
    for (int j = 0; j < num_of_expired_keys; j++) {
        GUARD_AS_POSIX(s2n_set_remove(config->ticket_keys, expired_keys_index[j] - j));
    }

    return 0;
}


int s2n_config_store_ticket_key(struct s2n_config *config, struct s2n_ticket_key *key)
{
    /* Keys are stored from oldest to newest */
    GUARD_AS_POSIX(s2n_set_add(config->ticket_keys, key));
    return S2N_SUCCESS;
}
