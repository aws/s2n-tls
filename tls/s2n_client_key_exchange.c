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

#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_kem.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_resume.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
typedef int s2n_kex_client_key_method(const struct s2n_kex *kex, struct s2n_connection *conn, struct s2n_blob *shared_key);
typedef void *s2n_stuffer_action(struct s2n_stuffer *stuffer, uint32_t data_len);
static int s2n_hybrid_client_action(struct s2n_connection *conn, struct s2n_blob *combined_shared_key,
        s2n_kex_client_key_method kex_method, uint32_t *cursor, s2n_stuffer_action stuffer_action)
{
    notnull_check(kex_method);
    notnull_check(stuffer_action);
    struct s2n_stuffer *io = &conn->handshake.io;
    const struct s2n_kex *kex = conn->secure.cipher_suite->key_exchange_alg;
    const struct s2n_kex *hybrid_kex_0 = kex->hybrid[0];
    const struct s2n_kex *hybrid_kex_1 = kex->hybrid[1];

    /* Keep a copy to the start of the entire hybrid client key exchange message for the hybrid PRF */
    struct s2n_blob *client_key_exchange_message = &conn->secure.client_key_exchange_message;
    client_key_exchange_message->data = stuffer_action(io, 0);
    notnull_check(client_key_exchange_message->data);
    const uint32_t start_cursor = *cursor;

    DEFER_CLEANUP(struct s2n_blob shared_key_0 = {0}, s2n_free);
    GUARD(kex_method(hybrid_kex_0, conn, &shared_key_0));

    DEFER_CLEANUP(struct s2n_blob shared_key_1 = {0}, s2n_free);
    GUARD(kex_method(hybrid_kex_1, conn, &shared_key_1));

    const uint32_t end_cursor = *cursor;
    gte_check(end_cursor, start_cursor);
    client_key_exchange_message->size = end_cursor - start_cursor;

    GUARD(s2n_alloc(combined_shared_key, shared_key_0.size + shared_key_1.size));
    struct s2n_stuffer stuffer_combiner = {0};
    GUARD(s2n_stuffer_init(&stuffer_combiner, combined_shared_key));
    GUARD(s2n_stuffer_write(&stuffer_combiner, &shared_key_0));
    GUARD(s2n_stuffer_write(&stuffer_combiner, &shared_key_1));

    return 0;
}

static int calculate_keys(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_kex_tls_prf(conn->secure.cipher_suite->key_exchange_alg, conn, shared_key));
    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(shared_key));
    if (shared_key->allocated) {
        GUARD(s2n_free(shared_key));
    }
    /* Expand the keys */
    GUARD(s2n_prf_key_expansion(conn));
    /* Save the master secret in the cache */
    if (s2n_allowed_to_cache_connection(conn)) {
        GUARD(s2n_store_to_cache(conn));
    }
    return 0;
}

int s2n_rsa_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    uint16_t length;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = s2n_stuffer_data_available(in);
    } else {
        GUARD(s2n_stuffer_read_uint16(in, &length));
    }

    S2N_ERROR_IF(length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    /* Keep a copy of the client protocol version in wire format */
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    /* Decrypt the pre-master secret */
    shared_key->data = conn->secure.rsa_premaster_secret;
    shared_key->size = S2N_TLS_SECRET_LEN;

    struct s2n_blob encrypted = {.size = length, .data = s2n_stuffer_raw_read(in, length)};
    notnull_check(encrypted.data);
    gt_check(encrypted.size, 0);

    /* First: use a random pre-master secret */
    GUARD(s2n_get_private_random_data(shared_key));
    conn->secure.rsa_premaster_secret[0] = client_protocol_version[0];
    conn->secure.rsa_premaster_secret[1] = client_protocol_version[1];

    /* Set rsa_failed to 1 if s2n_pkey_decrypt returns anything other than zero */
    conn->handshake.rsa_failed = !!s2n_pkey_decrypt(conn->handshake_params.our_chain_and_key->private_key, &encrypted, shared_key);

    /* Set rsa_failed to 1, if it isn't already, if the protocol version isn't what we expect */
    conn->handshake.rsa_failed |= !s2n_constant_time_equals(client_protocol_version, shared_key->data, S2N_TLS_PROTOCOL_VERSION_LEN);
    return 0;
}

int s2n_dhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* Get the shared key */
    GUARD(s2n_dh_compute_shared_secret_as_server(&conn->secure.server_dh_params, in, shared_key));
    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    return 0;
}

int s2n_ecdhe_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    /* Get the shared key */
    GUARD(s2n_ecc_evp_compute_shared_secret_as_server(&conn->secure.server_ecc_evp_params, in, shared_key));
    /* We don't need the server params any more */
    GUARD(s2n_ecc_evp_params_free(&conn->secure.server_ecc_evp_params));
    return 0;
}

int s2n_kem_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    kem_ciphertext_key_size ciphertext_length;

    GUARD(s2n_stuffer_read_uint16(in, &ciphertext_length));
    S2N_ERROR_IF(ciphertext_length > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    const struct s2n_blob ciphertext = {.size = ciphertext_length, .data = s2n_stuffer_raw_read(in, ciphertext_length)};
    notnull_check(ciphertext.data);

    GUARD(s2n_kem_decapsulate(&conn->secure.s2n_kem_keys, shared_key, &ciphertext));

    GUARD(s2n_kem_free(&conn->secure.s2n_kem_keys));
    return 0;
}

int s2n_hybrid_client_key_recv(struct s2n_connection *conn, struct s2n_blob *combined_shared_key)
{
    return s2n_hybrid_client_action(conn, combined_shared_key, &s2n_kex_client_key_recv, &conn->handshake.io.read_cursor,
            &s2n_stuffer_raw_read);
}

int s2n_client_key_recv(struct s2n_connection *conn)
{
    const struct s2n_kex *key_exchange = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(s2n_kex_client_key_recv(key_exchange, conn, &shared_key));

    GUARD(calculate_keys(conn, &shared_key));
    return 0;
}

int s2n_dhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    GUARD(s2n_dh_compute_shared_secret_as_client(&conn->secure.server_dh_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_dh_params_free(&conn->secure.server_dh_params));
    return 0;
}

int s2n_ecdhe_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    GUARD(s2n_ecc_evp_compute_shared_secret_as_client(&conn->secure.server_ecc_evp_params, out, shared_key));

    /* We don't need the server params any more */
    GUARD(s2n_ecc_evp_params_free(&conn->secure.server_ecc_evp_params));
    return 0;
}

int s2n_rsa_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    uint8_t client_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_protocol_version[0] = conn->client_protocol_version / 10;
    client_protocol_version[1] = conn->client_protocol_version % 10;

    shared_key->data = conn->secure.rsa_premaster_secret;
    shared_key->size = S2N_TLS_SECRET_LEN;

    GUARD(s2n_get_private_random_data(shared_key));

    /* Over-write the first two bytes with the client protocol version, per RFC2246 7.4.7.1 */
    memcpy_check(conn->secure.rsa_premaster_secret, client_protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN);

    int encrypted_size = s2n_pkey_size(&conn->secure.server_public_key);
    S2N_ERROR_IF(encrypted_size < 0 || encrypted_size > 0xffff, S2N_ERR_SIZE_MISMATCH);

    if (conn->actual_protocol_version > S2N_SSLv3) {
        GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, encrypted_size));
    }

    struct s2n_blob encrypted = {0};
    encrypted.data = s2n_stuffer_raw_write(&conn->handshake.io, encrypted_size);
    encrypted.size = encrypted_size;
    notnull_check(encrypted.data);

    /* Encrypt the secret and send it on */
    GUARD(s2n_pkey_encrypt(&conn->secure.server_public_key, shared_key, &encrypted));

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));
    return 0;
}

int s2n_kem_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    struct s2n_stuffer *out = &conn->handshake.io;
    const struct s2n_kem *kem = conn->secure.s2n_kem_keys.negotiated_kem;

    GUARD(s2n_stuffer_write_uint16(out, kem->ciphertext_length));

    /* The ciphertext is not needed after this method, write it straight to the stuffer */
    struct s2n_blob ciphertext = {.data = s2n_stuffer_raw_write(out, kem->ciphertext_length), .size = kem->ciphertext_length};
    notnull_check(ciphertext.data);

    GUARD(s2n_kem_encapsulate(&conn->secure.s2n_kem_keys, shared_key, &ciphertext));
    GUARD(s2n_kem_free(&conn->secure.s2n_kem_keys));
    return 0;
}

int s2n_hybrid_client_key_send(struct s2n_connection *conn, struct s2n_blob *combined_shared_key)
{
    return s2n_hybrid_client_action(conn, combined_shared_key, &s2n_kex_client_key_send, &conn->handshake.io.write_cursor,
                                    s2n_stuffer_raw_write);
}

int s2n_client_key_send(struct s2n_connection *conn)
{
    const struct s2n_kex *key_exchange = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(s2n_kex_client_key_send(key_exchange, conn, &shared_key));

    GUARD(calculate_keys(conn, &shared_key));
    return 0;
}
