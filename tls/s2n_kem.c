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

#include <utils/s2n_safety.h>
#include "tls/s2n_connection.h"
#include "tls/s2n_kem_core.h"
#include "tls/s2n_tls_digest_preferences.h"
#include "s2n_resume.h"
#include "s2n_cipher_suites.h"

static int s2n_write_signature_blob(struct s2n_stuffer *out, const struct s2n_pkey *priv_key, struct s2n_hash_state *digest);

static int calculate_keys(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    /* Turn the pre-master secret into a master secret */
    GUARD(s2n_prf_master_secret(conn, shared_key));

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

int s2n_server_key_recv(struct s2n_connection *conn)
{
    struct s2n_hash_state *signature_hash = &conn->secure.signature_hash;
    struct s2n_kem_core *kem_core = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob data_to_sign = {0};


    /* Read and process the KEM data */
    GUARD(kem_core->server_key_recv(conn, &data_to_sign));

    /* Add common signature data */
    if (conn->actual_protocol_version == S2N_TLS12) {
        s2n_hash_algorithm hash_algorithm;
        s2n_signature_algorithm signature_algorithm;
        GUARD(s2n_get_signature_hash_pair_if_supported(in, &hash_algorithm, &signature_algorithm));

        GUARD(s2n_hash_init(signature_hash, hash_algorithm));
    } else {
        GUARD(s2n_hash_init(signature_hash, conn->secure.conn_hash_alg));
    }
    GUARD(s2n_hash_update(signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));

    /* Add KEM specific data */
    GUARD(s2n_hash_update(signature_hash, data_to_sign.data, data_to_sign.size));

    /* Verify the signature */
    struct s2n_blob signature = {0};
    uint16_t signature_length;
    GUARD(s2n_stuffer_read_uint16(in, &signature_length));
    signature.size = signature_length;
    signature.data = s2n_stuffer_raw_read(in, signature.size);
    notnull_check(signature.data);
    gt_check(signature_length, 0);

    S2N_ERROR_IF(s2n_pkey_verify(&conn->secure.server_public_key, signature_hash, &signature) < 0, S2N_ERR_BAD_MESSAGE);

    /* We don't need the key any more, so free it */
    GUARD(s2n_pkey_free(&conn->secure.server_public_key));

    return 0;
}

int s2n_server_key_send(struct s2n_connection *conn)
{
    struct s2n_hash_state *signature_hash = &conn->secure.signature_hash;
    struct s2n_kem_core *kem_core = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_stuffer *out = &conn->handshake.io;
    struct s2n_blob data_to_sign = {0};

    /* Process and send the KEM data */
    GUARD(kem_core->server_key_send(conn, &data_to_sign));

    /* Add common signature data */
    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_hash_alg_to_tls[ conn->secure.conn_hash_alg ]));
        GUARD(s2n_stuffer_write_uint8(out, conn->secure.conn_sig_alg));
    }

    /* Add the random data to the hash */
    GUARD(s2n_hash_init(signature_hash, conn->secure.conn_hash_alg));
    GUARD(s2n_hash_update(signature_hash, conn->secure.client_random, S2N_TLS_RANDOM_DATA_LEN));
    GUARD(s2n_hash_update(signature_hash, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN));

    /* Add KEM specific data */
    GUARD(s2n_hash_update(signature_hash, data_to_sign.data, data_to_sign.size));

    /* Sign and write the signature */
    GUARD(s2n_write_signature_blob(out, &conn->config->cert_and_key_pairs->private_key, signature_hash));

    return 0;
}

int s2n_client_key_recv(struct s2n_connection *conn)
{
    struct s2n_kem_core *kem_core = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};
    GUARD(kem_core->client_key_recv(conn, &shared_key));
    GUARD(calculate_keys(conn, &shared_key));
    return 0;
}

int s2n_client_key_send(struct s2n_connection *conn)
{
    struct s2n_kem_core *kem_core = conn->secure.cipher_suite->key_exchange_alg;
    struct s2n_blob shared_key = {0};

    GUARD(kem_core->client_key_send(conn, &shared_key));
    GUARD(calculate_keys(conn, &shared_key));

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
