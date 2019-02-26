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

#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_signature_algorithms.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

static int s2n_ecdhe_server_key_send_external(struct s2n_connection *conn);
static int s2n_dhe_server_key_send_external(struct s2n_connection *conn);
static int s2n_ecdhe_server_key_recv(struct s2n_connection *conn);
static int s2n_dhe_server_key_recv(struct s2n_connection *conn);
static int s2n_ecdhe_server_key_send(struct s2n_connection *conn);
static int s2n_dhe_server_key_send(struct s2n_connection *conn);
static int s2n_write_io_with_external_result(struct s2n_connection *conn);
static int s2n_write_signature_blob(struct s2n_stuffer *out, const struct s2n_pkey *priv_key, struct s2n_hash_state *digest);
static int s2n_sign_external(dhe_sign_async_fn external_sign_fn, s2n_hash_algorithm hash_algorithm, struct s2n_hash_state *hash_state, uint8_t *status, uint8_t **result);

int s2n_server_key_recv(struct s2n_connection *conn)
{
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecdhe_server_key_recv(conn));
    } else {
        GUARD(s2n_dhe_server_key_recv(conn));
    }
    return 0;
}

static int s2n_ecdhe_server_key_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob ecdhparams = {0};
    struct s2n_blob signature = {0};
    uint16_t signature_length;

    /* Read server ECDH params and calculate their hash */
    GUARD(s2n_ecc_read_ecc_params(&conn->secure.server_ecc_params, in, &ecdhparams));

    if (conn->actual_protocol_version == S2N_TLS12) {
        s2n_hash_algorithm hash_algorithm;
        s2n_signature_algorithm signature_algorithm;
        GUARD(s2n_get_signature_hash_pair_if_supported(in, &hash_algorithm, &signature_algorithm));

        GUARD(s2n_hash_init(&conn->secure.signature_hash, hash_algorithm));
    } else {
        GUARD(s2n_hash_init(&conn->secure.signature_hash, conn->secure.conn_hash_alg));
    }
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, ecdhparams.data, ecdhparams.size));

    /* Verify the signature */
    GUARD(s2n_stuffer_read_uint16(in, &signature_length));
    signature.size = signature_length;
    signature.data = s2n_stuffer_raw_read(in, signature.size);
    notnull_check(signature.data);
    gt_check(signature_length, 0);

    S2N_ERROR_IF(s2n_pkey_verify(&conn->secure.server_public_key, &conn->secure.signature_hash, &signature) < 0, S2N_ERR_BAD_MESSAGE);

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));
    return 0;
}

static int s2n_dhe_server_key_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob p, g, Ys, serverDHparams, signature;
    uint16_t p_length;
    uint16_t g_length;
    uint16_t Ys_length;
    uint16_t signature_length;

    /* Keep a copy to the start of the whole structure for the signature check */
    serverDHparams.data = s2n_stuffer_raw_read(in, 0);
    notnull_check(serverDHparams.data);

    /* Read each of the three elements in */
    GUARD(s2n_stuffer_read_uint16(in, &p_length));
    p.size = p_length;
    p.data = s2n_stuffer_raw_read(in, p.size);
    notnull_check(p.data);

    GUARD(s2n_stuffer_read_uint16(in, &g_length));
    g.size = g_length;
    g.data = s2n_stuffer_raw_read(in, g.size);
    notnull_check(g.data);

    GUARD(s2n_stuffer_read_uint16(in, &Ys_length));
    Ys.size = Ys_length;
    Ys.data = s2n_stuffer_raw_read(in, Ys.size);
    notnull_check(Ys.data);

    /* Now we know the total size of the structure */
    serverDHparams.size = 2 + p_length + 2 + g_length + 2 + Ys_length;

    if (conn->actual_protocol_version == S2N_TLS12) {
        s2n_hash_algorithm hash_algorithm;
        s2n_signature_algorithm signature_algorithm;
        GUARD(s2n_get_signature_hash_pair_if_supported(in, &hash_algorithm, &signature_algorithm));

        GUARD(s2n_hash_init(&conn->secure.signature_hash, hash_algorithm));
    } else {
        GUARD(s2n_hash_init(&conn->secure.signature_hash, conn->secure.conn_hash_alg));
    }

    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, serverDHparams.data, serverDHparams.size));

    GUARD(s2n_stuffer_read_uint16(in, &signature_length));
    signature.size = signature_length;
    signature.data = s2n_stuffer_raw_read(in, signature.size);
    notnull_check(signature.data);

    gt_check(signature_length, 0);

    S2N_ERROR_IF(s2n_pkey_verify(&conn->secure.server_public_key, &conn->secure.signature_hash, &signature) < 0, S2N_ERR_BAD_MESSAGE);

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));

    /* Copy the DH details */
    GUARD(s2n_dh_p_g_Ys_to_dh_params(&conn->secure.server_dh_params, &p, &g, &Ys));

    return 0;
}

static int s2n_free_external_ctx_signed_hash(struct s2n_connection *conn)
{
    notnull_check(conn);
    free(conn->external_ctx.signed_hash);
    conn->external_ctx.signed_hash = NULL;
    conn->external_ctx.signed_hash_size = 0;

    return 0;
}

int s2n_server_key_send_external(struct s2n_connection *conn)
{
    notnull_check(conn);
    notnull_check(conn->config);

    if (NULL == conn->config->external_dhe_sign) {
        return 0;
    }

    switch(conn->external_ctx.sign_status) {
        /* external signing has not been invoked yet */
        case S2N_EXTERNAL_NOT_INVOKED: {
            if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
                GUARD(s2n_ecdhe_server_key_send_external(conn));
            } else {
                GUARD(s2n_dhe_server_key_send_external(conn));
            }

            /* Return '1' to indicate we are waiting for the result now */
            return 1;
        }
        /* external signing has been invoked and we are waiting for the result. Return '1' to indicate that */
        case S2N_EXTERNAL_INVOKED: {
            return 1;
        }
        /* external signing has returned the result. Proceed by returning '0' */
        case S2N_EXTERNAL_RETURNED: {
            return 0;
        }
        /* error occurred with the external signing */
        case S2N_EXTERNAL_ERROR: {
            /* free the ctx */
            s2n_free_external_ctx_signed_hash(conn);
            S2N_ERROR(S2N_ERR_EXTERNAL_FAILURE);
        }
        /* the status is not anything we expected. Something went wrong. */
        default: {
            /* free the ctx */
            s2n_free_external_ctx_signed_hash(conn);
            S2N_ERROR(S2N_ERR_EXTERNAL_CTX_STATUS_INVALID);
        }
    }
}

static int s2n_sign_external(dhe_sign_async_fn external_sign_fn, s2n_hash_algorithm hash_algorithm, struct s2n_hash_state *hash_state, int32_t *status, uint8_t **result)
{
    // prepare the digest_out blob
    uint32_t digest_out_length = S2N_MAX_DIGEST_LEN;
    struct s2n_blob digest_out;
    s2n_alloc(&digest_out, digest_out_length);

    uint8_t digest_size;
    GUARD(s2n_hash_digest_size(hash_algorithm, &digest_size));
    GUARD(s2n_hash_digest(hash_state, digest_out.data, digest_size));

    *status = 1;
    external_sign_fn(status, result, (uint8_t)hash_algorithm, digest_out.data);

    s2n_free(&digest_out);

    return 0;
}

static int s2n_ecdhe_server_key_send_external(struct s2n_connection *conn)
{
    struct s2n_blob ecdhparams = {0};
    struct s2n_stuffer *out = &conn->external_ctx.ephemeral_key_io;
    s2n_stuffer_resize(out, 1024);

    /* Generate an ephemeral key and  */
    GUARD(s2n_ecc_generate_ephemeral_key(&conn->secure.server_ecc_params));

    /* Write it out and calculate the hash */
    GUARD(s2n_ecc_write_ecc_params(&conn->secure.server_ecc_params, out, &ecdhparams));

    /* Add the random data to the hash */
    GUARD(s2n_hash_init(&conn->secure.signature_hash, conn->secure.conn_hash_alg));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, ecdhparams.data, ecdhparams.size));

    GUARD(s2n_sign_external(conn->config->external_dhe_sign,
                            conn->secure.signature_hash.alg,
                            &(conn->secure.signature_hash),
                            &(conn->external_ctx.sign_status),
                            &(conn->external_ctx.signed_hash)));

    return 0;
}

static int s2n_dhe_server_key_send_external(struct s2n_connection *conn)
{
    struct s2n_blob serverDHparams;
    struct s2n_stuffer *out = &conn->config->external_dhe_ctx.ephemeral_key_io;
    s2n_stuffer_growable_alloc(out, 1024);

    /* Duplicate the DH key from the config */
    GUARD(s2n_dh_params_copy(conn->config->dhparams, &conn->secure.server_dh_params));

    /* Generate an ephemeral key */
    GUARD(s2n_dh_generate_ephemeral_key(&conn->secure.server_dh_params));

    /* Write it out */
    GUARD(s2n_dh_params_to_p_g_Ys(&conn->secure.server_dh_params, out, &serverDHparams));

    GUARD(s2n_hash_init(&conn->secure.signature_hash, conn->secure.conn_hash_alg));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, serverDHparams.data, serverDHparams.size));

    GUARD(s2n_sign_external(conn->config->external_dhe_sign,
                            conn->secure.signature_hash.alg,
                            &(conn->secure.signature_hash),
                            &(conn->config->external_dhe_ctx.status),
                            &(conn->config->external_dhe_ctx.result)));

    return 0;
}

int s2n_server_key_send(struct s2n_connection *conn)
{
    if (conn->secure.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC) {
        GUARD(s2n_ecdhe_server_key_send(conn));
    } else {
        GUARD(s2n_dhe_server_key_send(conn));
    }

    return 0;
}

static int s2n_ecdhe_server_key_send(struct s2n_connection *conn)
{
    /* if its external signing, just need to write the io with the external signing result */
    if (conn->config->external_dhe_sign) {
        return s2n_write_io_with_external_result(conn);
    }

    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_blob ecdhparams = {0};

    /* Generate an ephemeral key and  */
    GUARD(s2n_ecc_generate_ephemeral_key(&conn->secure.server_ecc_params));

    /* Write it out and calculate the hash */
    GUARD(s2n_ecc_write_ecc_params(&conn->secure.server_ecc_params, out, &ecdhparams));

    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_hash_alg_to_tls[ conn->secure.conn_hash_alg ]));
        GUARD(s2n_stuffer_write_uint8(out, conn->secure.conn_sig_alg));
    }

    /* Add the random data to the hash */
    GUARD(s2n_hash_init(&conn->secure.signature_hash, conn->secure.conn_hash_alg));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, ecdhparams.data, ecdhparams.size));

    GUARD(s2n_write_signature_blob(out, &conn->config->cert_and_key_pairs->private_key, &conn->secure.signature_hash));

    return 0;
}

static int s2n_dhe_server_key_send(struct s2n_connection *conn)
{
    /* if its external signing, just need to write the io with the external signing result */
    if (conn->config->external_dhe_sign) {
        return s2n_write_io_with_external_result(conn);
    }

    struct s2n_blob serverDHparams;
    struct s2n_stuffer *out = &conn->handshake.io;

    /* Duplicate the DH key from the config */
    GUARD(s2n_dh_params_copy(conn->config->dhparams, &conn->secure.server_dh_params));

    /* Generate an ephemeral key */
    GUARD(s2n_dh_generate_ephemeral_key(&conn->secure.server_dh_params));

    /* Write it out */
    GUARD(s2n_dh_params_to_p_g_Ys(&conn->secure.server_dh_params, out, &serverDHparams));

    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_hash_alg_to_tls[ conn->secure.conn_hash_alg ]));
        GUARD(s2n_stuffer_write_uint8(out, conn->secure.conn_sig_alg));
    }

    GUARD(s2n_hash_init(&conn->secure.signature_hash, conn->secure.conn_hash_alg));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(&conn->secure.signature_hash, serverDHparams.data, serverDHparams.size));

    GUARD(s2n_write_signature_blob(out, &conn->config->cert_and_key_pairs->private_key, &conn->secure.signature_hash));

    return 0;
}

static int s2n_write_io_with_external_result(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    /* The ephemeral key has already been generated */
    struct s2n_stuffer *ephemeral_key = &conn->external_ctx.ephemeral_key_io;
    GUARD(s2n_stuffer_copy(ephemeral_key, out, ephemeral_key->write_cursor));

    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_hash_alg_to_tls[ conn->secure.conn_hash_alg ]));
        GUARD(s2n_stuffer_write_uint8(out, conn->secure.conn_sig_alg));
    }

    uint8_t *result = conn->external_ctx.signed_hash;
    notnull_check(result);
    uint32_t size = conn->external_ctx.signed_hash_size;
    GUARD(s2n_stuffer_write_uint16(out, size));
    GUARD(s2n_stuffer_write_bytes(out, result, size));

    /* free the ctx */
    s2n_free_external_ctx_signed_hash(conn);

    return 0;
}

static int s2n_write_signature_blob(struct s2n_stuffer *out, const struct s2n_pkey *priv_key, struct s2n_hash_state *digest)
{
    struct s2n_blob signature = {0};
    
    /* Leave signature length blank for now until we're done signing */
    uint16_t sig_len = 0;
    GUARD(s2n_stuffer_write_uint16(out, sig_len));
    
    int max_signature_size = s2n_pkey_size(priv_key);
    signature.size = max_signature_size;
    signature.data = s2n_stuffer_raw_write(out, signature.size);
    notnull_check(signature.data);

    S2N_ERROR_IF(s2n_pkey_sign(priv_key, digest, &signature) < 0, S2N_ERR_DH_FAILED_SIGNING);

    /* Now that the signature has been created, write the actual size that was stored in the signature blob */
    out->write_cursor -= max_signature_size;
    out->write_cursor -= 2;

    GUARD(s2n_stuffer_write_uint16(out, signature.size));
    GUARD(s2n_stuffer_skip_write(out, signature.size));

    return 0;
}
