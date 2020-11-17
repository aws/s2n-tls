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

#include "crypto/s2n_tls13_keys.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_psk.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

int s2n_psk_init(struct s2n_psk *psk, s2n_psk_type type)
{
    notnull_check(psk);

    memset_check(psk, 0, sizeof(struct s2n_psk));
    psk->hash_alg = S2N_HASH_SHA256;
    psk->type = type;

    return S2N_SUCCESS;
}

int s2n_psk_new_identity(struct s2n_psk *psk, const uint8_t *identity, size_t identity_size)
{
    notnull_check(psk);

    GUARD(s2n_realloc(&psk->identity, identity_size));
    memcpy_check(psk->identity.data, identity, identity_size);

    return S2N_SUCCESS;
}

int s2n_psk_new_secret(struct s2n_psk *psk, const uint8_t *secret, size_t secret_size)
{
    notnull_check(psk);

    GUARD(s2n_realloc(&psk->secret, secret_size));
    memcpy_check(psk->secret.data, secret, secret_size);

    return S2N_SUCCESS;
}

int s2n_psk_free(struct s2n_psk *psk)
{
    notnull_check(psk);

    GUARD(s2n_free(&psk->early_secret));
    GUARD(s2n_free(&psk->identity));
    GUARD(s2n_free(&psk->secret));

    return S2N_SUCCESS;
}

int s2n_psk_calculate_binder_hash(struct s2n_connection *conn, s2n_hash_algorithm hash_alg,
        const struct s2n_blob *partial_client_hello, struct s2n_blob *output_binder_hash)
{
    notnull_check(partial_client_hello);
    notnull_check(output_binder_hash);

    /* Retrieve the current transcript.
     * The current transcript will be empty unless this handshake included a HelloRetryRequest. */
    struct s2n_hash_state current_hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, hash_alg, &current_hash_state));

    /* Copy the current transcript to avoid modifying the original. */
    DEFER_CLEANUP(struct s2n_hash_state hash_copy, s2n_hash_free);
    GUARD(s2n_hash_new(&hash_copy));
    GUARD(s2n_hash_copy(&hash_copy, &current_hash_state));

    /* Add the partial client hello to the transcript. */
    GUARD(s2n_hash_update(&hash_copy, partial_client_hello->data, partial_client_hello->size));

    /* Get the transcript digest */
    GUARD(s2n_hash_digest(&hash_copy, output_binder_hash->data, output_binder_hash->size));

    return S2N_SUCCESS;
}

static int s2n_tls13_keys_init_with_psk(struct s2n_tls13_keys *keys, struct s2n_psk *psk)
{
    notnull_check(keys);

    keys->hash_algorithm = psk->hash_alg;
    GUARD(s2n_hash_hmac_alg(keys->hash_algorithm, &keys->hmac_algorithm));
    GUARD(s2n_hash_digest_size(keys->hash_algorithm, &keys->size));
    GUARD(s2n_blob_init(&keys->extract_secret, keys->extract_secret_bytes, keys->size));
    GUARD(s2n_blob_init(&keys->derive_secret, keys->derive_secret_bytes, keys->size));
    GUARD(s2n_hmac_new(&keys->hmac));

    return S2N_SUCCESS;
}

int s2n_psk_calculate_binder(struct s2n_psk *psk, const struct s2n_blob *binder_hash,
        struct s2n_blob *output_binder)
{
    notnull_check(psk);
    notnull_check(binder_hash);
    notnull_check(output_binder);

    DEFER_CLEANUP(struct s2n_tls13_keys psk_keys, s2n_tls13_keys_free);
    GUARD(s2n_tls13_keys_init_with_psk(&psk_keys, psk));
    eq_check(binder_hash->size, psk_keys.size);
    eq_check(output_binder->size, psk_keys.size);

    /* Make sure the early secret is saved on the psk structure for later use */
    GUARD(s2n_alloc(&psk->early_secret, psk_keys.size));
    GUARD(s2n_blob_init(&psk_keys.extract_secret, psk->early_secret.data, psk_keys.size));

    /* Derive the binder key */
    GUARD(s2n_tls13_derive_binder_key_secret(&psk_keys, psk));
    struct s2n_blob *binder_key = &psk_keys.derive_secret;

    /* Expand the binder key into the finished key */
    s2n_tls13_key_blob(finished_key, psk_keys.size);
    GUARD(s2n_tls13_derive_finished_key(&psk_keys, binder_key, &finished_key));

    /* HMAC the binder hash with the binder finished key */
    GUARD(s2n_hkdf_extract(&psk_keys.hmac, psk_keys.hmac_algorithm, &finished_key, binder_hash, output_binder));

    return S2N_SUCCESS;
}

int s2n_psk_verify_binder(struct s2n_connection *conn, struct s2n_psk *psk,
        const struct s2n_blob *partial_client_hello, struct s2n_blob *binder_to_verify)
{
    notnull_check(psk);
    notnull_check(binder_to_verify);

    DEFER_CLEANUP(struct s2n_tls13_keys psk_keys, s2n_tls13_keys_free);
    GUARD(s2n_tls13_keys_init_with_psk(&psk_keys, psk));
    eq_check(binder_to_verify->size, psk_keys.size);

    /* Calculate the binder hash from the transcript */
    s2n_tls13_key_blob(binder_hash, psk_keys.size);
    GUARD(s2n_psk_calculate_binder_hash(conn, psk->hash_alg, partial_client_hello, &binder_hash));

    /* Calculate the expected binder from the binder hash */
    s2n_tls13_key_blob(expected_binder, psk_keys.size);
    GUARD(s2n_psk_calculate_binder(psk, &binder_hash, &expected_binder));

    /* Verify the expected binder matches the given binder.
     * This operation must be constant time. */
    GUARD(s2n_tls13_mac_verify(&psk_keys, &expected_binder, binder_to_verify));

    return S2N_SUCCESS;
}
