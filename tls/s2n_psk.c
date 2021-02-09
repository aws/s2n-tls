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
#include "tls/s2n_tls.h"

#include "utils/s2n_array.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

#define S2N_HASH_ALG_COUNT S2N_HASH_SENTINEL
#define S2N_MAX_OFFERED_PSK_LIST_SIZE (UINT16_MAX - sizeof(uint16_t) /* extension type */ - sizeof(uint16_t) /* extension size */)

S2N_RESULT s2n_psk_init(struct s2n_psk *psk, s2n_psk_type type)
{
    ENSURE_MUT(psk);

    CHECKED_MEMSET(psk, 0, sizeof(struct s2n_psk));
    psk->hmac_alg = S2N_HMAC_SHA256;
    psk->type = type;

    return S2N_RESULT_OK;
}

struct s2n_psk* s2n_external_psk_new()
{
    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    GUARD_PTR(s2n_alloc(&mem, sizeof(struct s2n_psk)));

    struct s2n_psk *psk = (struct s2n_psk*)(void*) mem.data;
    GUARD_RESULT_PTR(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));

    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return psk;
}

int s2n_psk_set_identity(struct s2n_psk *psk, const uint8_t *identity, uint16_t identity_size)
{
    notnull_check(psk);
    notnull_check(identity);
    ENSURE_POSIX(identity_size != 0, S2N_ERR_INVALID_ARGUMENT);

    GUARD(s2n_realloc(&psk->identity, identity_size));
    memcpy_check(psk->identity.data, identity, identity_size);

    return S2N_SUCCESS;
}

int s2n_psk_set_secret(struct s2n_psk *psk, const uint8_t *secret, uint16_t secret_size)
{
    notnull_check(psk);
    notnull_check(secret);
    ENSURE_POSIX(secret_size != 0, S2N_ERR_INVALID_ARGUMENT);

    GUARD(s2n_realloc(&psk->secret, secret_size));
    memcpy_check(psk->secret.data, secret, secret_size);

    return S2N_SUCCESS;
}

S2N_CLEANUP_RESULT s2n_psk_wipe(struct s2n_psk *psk)
{
    if (psk == NULL) {
        return S2N_RESULT_OK;
    }

    GUARD_AS_RESULT(s2n_free(&psk->early_secret));
    GUARD_AS_RESULT(s2n_free(&psk->identity));
    GUARD_AS_RESULT(s2n_free(&psk->secret));

    return S2N_RESULT_OK;
}

int s2n_psk_free(struct s2n_psk **psk)
{
    if (psk == NULL) {
        return S2N_SUCCESS;
    }
    GUARD_AS_POSIX(s2n_psk_wipe(*psk));
    return s2n_free_object((uint8_t **) psk, sizeof(struct s2n_psk));
}

S2N_RESULT s2n_psk_parameters_init(struct s2n_psk_parameters *params)
{
    ENSURE_REF(params);
    CHECKED_MEMSET(params, 0, sizeof(struct s2n_psk_parameters));
    GUARD_RESULT(s2n_array_init(&params->psk_list, sizeof(struct s2n_psk)));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_psk_parameters_offered_psks_size(struct s2n_psk_parameters *params, uint32_t *size)
{
    ENSURE_REF(params);
    ENSURE_REF(size);

    *size = sizeof(uint16_t)    /* identity list size */
          + sizeof(uint16_t)    /* binder list size */;

    const uint32_t static_size_per_identity = sizeof(uint16_t)  /* identity size */
                                            + sizeof(uint32_t)  /* obfuscated ticket age */
                                            + sizeof(uint8_t)   /* binder size */;

    for (uint32_t i = 0; i < params->psk_list.len; i++) {
        struct s2n_psk *psk = NULL;
        GUARD_RESULT(s2n_array_get(&params->psk_list, i, (void**)&psk));
        ENSURE_REF(psk);

        GUARD_AS_RESULT(s2n_add_overflow(*size, static_size_per_identity, size));
        GUARD_AS_RESULT(s2n_add_overflow(*size, psk->identity.size, size));

        uint8_t binder_size = 0;
        GUARD_AS_RESULT(s2n_hmac_digest_size(psk->hmac_alg, &binder_size));
        GUARD_AS_RESULT(s2n_add_overflow(*size, binder_size, size));
    }
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_psk_parameters_wipe(struct s2n_psk_parameters *params)
{
    ENSURE_REF(params);

    for (size_t i = 0; i < params->psk_list.len; i++) {
        struct s2n_psk *psk;
        GUARD_RESULT(s2n_array_get(&params->psk_list, i, (void**)&psk));
        GUARD_RESULT(s2n_psk_wipe(psk));
    }
    GUARD_AS_RESULT(s2n_free(&params->psk_list.mem));
    GUARD_RESULT(s2n_psk_parameters_init(params));

    return S2N_RESULT_OK;
}

/* The binder hash is computed by hashing the concatenation of the current transcript
 * and a partial ClientHello that does not include the binders themselves.
 */
int s2n_psk_calculate_binder_hash(struct s2n_connection *conn, s2n_hmac_algorithm hmac_alg,
        const struct s2n_blob *partial_client_hello, struct s2n_blob *output_binder_hash)
{
    notnull_check(partial_client_hello);
    notnull_check(output_binder_hash);

    /* Retrieve the current transcript.
     * The current transcript will be empty unless this handshake included a HelloRetryRequest. */
    struct s2n_hash_state current_hash_state = {0};

    s2n_hash_algorithm hash_alg;
    GUARD(s2n_hmac_hash_alg(hmac_alg, &hash_alg));
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

/* The binder is computed in the same way as the Finished message
 * (https://tools.ietf.org/html/rfc8446#section-4.4.4) but with the BaseKey being the binder_key
 * derived via the key schedule from the corresponding PSK which is being offered
 * (https://tools.ietf.org/html/rfc8446#section-7.1)
 */
int s2n_psk_calculate_binder(struct s2n_psk *psk, const struct s2n_blob *binder_hash,
        struct s2n_blob *output_binder)
{
    notnull_check(psk);
    notnull_check(binder_hash);
    notnull_check(output_binder);

    DEFER_CLEANUP(struct s2n_tls13_keys psk_keys, s2n_tls13_keys_free);
    GUARD(s2n_tls13_keys_init(&psk_keys, psk->hmac_alg));
    eq_check(binder_hash->size, psk_keys.size);
    eq_check(output_binder->size, psk_keys.size);

    /* Make sure the early secret is saved on the psk structure for later use */
    GUARD(s2n_realloc(&psk->early_secret, psk_keys.size));
    GUARD(s2n_blob_init(&psk_keys.extract_secret, psk->early_secret.data, psk_keys.size));

    /* Derive the binder key */
    GUARD(s2n_tls13_derive_binder_key(&psk_keys, psk));
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
    GUARD(s2n_tls13_keys_init(&psk_keys, psk->hmac_alg));
    eq_check(binder_to_verify->size, psk_keys.size);

    /* Calculate the binder hash from the transcript */
    s2n_tls13_key_blob(binder_hash, psk_keys.size);
    GUARD(s2n_psk_calculate_binder_hash(conn, psk->hmac_alg, partial_client_hello, &binder_hash));

    /* Calculate the expected binder from the binder hash */
    s2n_tls13_key_blob(expected_binder, psk_keys.size);
    GUARD(s2n_psk_calculate_binder(psk, &binder_hash, &expected_binder));

    /* Verify the expected binder matches the given binder.
     * This operation must be constant time. */
    GUARD(s2n_tls13_mac_verify(&psk_keys, &expected_binder, binder_to_verify));

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_psk_write_binder(struct s2n_connection *conn, struct s2n_psk *psk,
        const struct s2n_blob *binder_hash, struct s2n_stuffer *out)
{
    ENSURE_REF(binder_hash);

    struct s2n_blob binder;
    uint8_t binder_data[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
    GUARD_AS_RESULT(s2n_blob_init(&binder, binder_data, binder_hash->size));

    GUARD_AS_RESULT(s2n_psk_calculate_binder(psk, binder_hash, &binder));
    GUARD_AS_RESULT(s2n_stuffer_write_uint8(out, binder.size));
    GUARD_AS_RESULT(s2n_stuffer_write(out, &binder));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_psk_write_binder_list(struct s2n_connection *conn, const struct s2n_blob *partial_client_hello,
        struct s2n_stuffer *out)
{
    ENSURE_REF(conn);
    ENSURE_REF(partial_client_hello);

    struct s2n_psk_parameters *psk_params = &conn->psk_params;
    struct s2n_array *psk_list = &psk_params->psk_list;

    /* Setup memory to hold the binder hashes. We potentially need one for
     * every hash algorithm. */
    uint8_t binder_hashes_data[S2N_HASH_ALG_COUNT][S2N_TLS13_SECRET_MAX_LEN] = { 0 };
    struct s2n_blob binder_hashes[S2N_HASH_ALG_COUNT] = { 0 };

    struct s2n_stuffer_reservation binder_list_size = { 0 };
    GUARD_AS_RESULT(s2n_stuffer_reserve_uint16(out, &binder_list_size));

    /* Write binder for every psk */
    for (size_t i = 0; i < psk_list->len; i++) {
        struct s2n_psk *psk = NULL;
        GUARD_RESULT(s2n_array_get(psk_list, i, (void**) &psk));
        ENSURE_REF(psk);

        /**
         *= https://tools.ietf.org/rfc/rfc8446#section-4.1.4
         *# In addition, in its updated ClientHello, the client SHOULD NOT offer
         *# any pre-shared keys associated with a hash other than that of the
         *# selected cipher suite.  This allows the client to avoid having to
         *# compute partial hash transcripts for multiple hashes in the second
         *# ClientHello.
         */
        if (s2n_is_hello_retry_handshake(conn) && conn->secure.cipher_suite->prf_alg != psk->hmac_alg) {
            continue;
        }

        /* Retrieve or calculate the binder hash. */
        struct s2n_blob *binder_hash = &binder_hashes[psk->hmac_alg];
        if (binder_hash->size == 0) {
            uint8_t hash_size = 0;
            GUARD_AS_RESULT(s2n_hmac_digest_size(psk->hmac_alg, &hash_size));
            GUARD_AS_RESULT(s2n_blob_init(binder_hash, binder_hashes_data[psk->hmac_alg], hash_size));
            GUARD_AS_RESULT(s2n_psk_calculate_binder_hash(conn, psk->hmac_alg, partial_client_hello, binder_hash));
        }

        GUARD_RESULT(s2n_psk_write_binder(conn, psk, binder_hash, out));
    }
    GUARD_AS_RESULT(s2n_stuffer_write_vector_size(&binder_list_size));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_finish_psk_extension(struct s2n_connection *conn)
{
    ENSURE_REF(conn);

    if (!conn->psk_params.binder_list_size) {
        return S2N_RESULT_OK;
    }

    struct s2n_stuffer *client_hello = &conn->handshake.io;
    struct s2n_psk_parameters *psk_params = &conn->psk_params;

    /* Fill in the correct message size. */
    GUARD_AS_RESULT(s2n_handshake_finish_header(client_hello));

    /* Remove the empty space allocated for the binder list.
     * It was originally added to ensure the extension / extension list / message sizes
     * were properly calculated. */
    GUARD_AS_RESULT(s2n_stuffer_wipe_n(client_hello, psk_params->binder_list_size));

    /* Store the partial client hello for use in calculating the binder hash. */
    struct s2n_blob partial_client_hello = { 0 };
    GUARD_AS_RESULT(s2n_blob_init(&partial_client_hello, client_hello->blob.data,
            s2n_stuffer_data_available(client_hello)));

    GUARD_RESULT(s2n_psk_write_binder_list(conn, &partial_client_hello, client_hello));
    return S2N_RESULT_OK;
}

int s2n_psk_set_hmac(struct s2n_psk *psk, s2n_psk_hmac hmac)
{
    notnull_check(psk);
    switch(hmac) {
        case S2N_PSK_HMAC_SHA224:     psk->hmac_alg = S2N_HMAC_SHA224; break;
        case S2N_PSK_HMAC_SHA256:     psk->hmac_alg = S2N_HMAC_SHA256; break;
        case S2N_PSK_HMAC_SHA384:     psk->hmac_alg = S2N_HMAC_SHA384; break;
        default:
            S2N_ERROR(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }
    return S2N_SUCCESS;
}

static S2N_CLEANUP_RESULT s2n_psk_parameters_wipe_external_psks(struct s2n_psk_parameters *params)
{
    ENSURE_REF(params);

    /* Remove non-external PSKs to avoid wiping them */
    for (uint32_t i = params->psk_list.len; i > 0; i--) {
        struct s2n_psk *psk = NULL;
        GUARD_RESULT(s2n_array_get(&params->psk_list, i - 1, (void**)&psk));
        ENSURE_REF(psk);
        if (psk->type == S2N_PSK_TYPE_EXTERNAL) {
            continue;
        }
        GUARD_RESULT(s2n_array_remove(&params->psk_list, i - 1));
    }

    /* Wipe */
    GUARD_RESULT(s2n_psk_parameters_wipe(params));
    return S2N_RESULT_OK;
}

int s2n_connection_set_external_psks(struct s2n_connection *conn, struct s2n_psk **psk_list, uint32_t psk_list_len)
{
    notnull_check(conn);
    
    /* To avoid corrupting existing PSKs on a failure, we will operate on a copy until successful */
    DEFER_CLEANUP(struct s2n_psk_parameters new_params = { 0 }, s2n_psk_parameters_wipe_external_psks);
    GUARD_AS_POSIX(s2n_psk_parameters_init(&new_params));

    /* Copy any non-external PSKs into the new list */
    for (uint32_t i = 0; i < conn->psk_params.psk_list.len; i++) {
        struct s2n_psk *existing_psk = NULL;
        GUARD_AS_POSIX(s2n_array_get(&conn->psk_params.psk_list, i, (void**) &existing_psk));
        notnull_check(existing_psk);

        if (existing_psk->type == S2N_PSK_TYPE_EXTERNAL) {
            continue;
        }
        GUARD_AS_POSIX(s2n_array_insert_and_copy(&new_params.psk_list, new_params.psk_list.len, existing_psk));
    }

    if (psk_list_len != 0) {
        notnull_check(psk_list);
    }

    for (uint32_t i = 0; i < psk_list_len; i++) {
        notnull_check(psk_list[i]);

        /* Check for duplicate identities */
        uint32_t array_len = new_params.psk_list.len;
        for (uint32_t j = 0; j < array_len; j++) {
            struct s2n_psk *existing_psk = NULL;
            GUARD_AS_POSIX(s2n_array_get(&new_params.psk_list, j, (void**) &existing_psk));
            notnull_check(existing_psk);

            bool duplicate = existing_psk->identity.size == psk_list[i]->identity.size
                    && memcmp(existing_psk->identity.data, psk_list[i]->identity.data, existing_psk->identity.size) == 0;
            ENSURE_POSIX(!duplicate, S2N_ERR_DUPLICATE_PSK_IDENTITIES);
        }

        struct s2n_psk *new_psk = NULL;
        GUARD_AS_POSIX(s2n_array_pushback(&new_params.psk_list, (void**) &new_psk));
        notnull_check(new_psk);

        GUARD_AS_POSIX(s2n_psk_init(new_psk, S2N_PSK_TYPE_EXTERNAL));
        ENSURE_POSIX(s2n_psk_set_identity(new_psk, psk_list[i]->identity.data, psk_list[i]->identity.size) == S2N_SUCCESS,
                S2N_ERR_INVALID_ARGUMENT);
        ENSURE_POSIX(s2n_psk_set_secret(new_psk, psk_list[i]->secret.data, psk_list[i]->secret.size) == S2N_SUCCESS,
                S2N_ERR_INVALID_ARGUMENT);
        new_psk->hmac_alg = psk_list[i]->hmac_alg;
    }

    /* Verify PSK list will fit in the ClientHello pre_shared_key extension */
    if (conn->mode == S2N_CLIENT) {
        uint32_t offered_psks_size = 0;
        GUARD_AS_POSIX(s2n_psk_parameters_offered_psks_size(&new_params, &offered_psks_size));
        ENSURE_POSIX(offered_psks_size <= S2N_MAX_OFFERED_PSK_LIST_SIZE, S2N_ERR_OFFERED_PSKS_TOO_LONG);
    }

    /* Finally, swap the old PSK list for the new PSK list */
    struct s2n_psk_parameters old_params = conn->psk_params;
    conn->psk_params = new_params;

    ZERO_TO_DISABLE_DEFER_CLEANUP(new_params);
    GUARD_AS_POSIX(s2n_psk_parameters_wipe_external_psks(&old_params));

    return S2N_SUCCESS;
}
