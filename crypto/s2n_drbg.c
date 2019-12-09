/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/evp.h>

#include "crypto/s2n_drbg.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

#define s2n_drbg_key_size(drgb) EVP_CIPHER_CTX_key_length((drbg)->ctx)
#define s2n_drbg_seed_size(drgb) (S2N_DRBG_BLOCK_SIZE + s2n_drbg_key_size(drgb))

/* This function is the same as s2n_increment_sequence_number
    but it does not check for overflow, since overflow is
    acceptable in DRBG */
int s2n_increment_drbg_counter(struct s2n_blob *counter)
{
    for (int i = counter->size - 1; i >= 0; i--) {
        counter->data[i] += 1;
        if (counter->data[i]) {
            break;
        }

       /* seq[i] wrapped, so let it carry */
    }
    return 0;
}

static int s2n_drbg_block_encrypt(EVP_CIPHER_CTX * ctx, uint8_t in[S2N_DRBG_BLOCK_SIZE], uint8_t out[S2N_DRBG_BLOCK_SIZE])
{
    notnull_check(ctx);
    int len = S2N_DRBG_BLOCK_SIZE;
    GUARD_OSSL(EVP_EncryptUpdate(ctx, out, &len, in, S2N_DRBG_BLOCK_SIZE), S2N_ERR_DRBG);
    eq_check(len, S2N_DRBG_BLOCK_SIZE);

    return 0;
}

static int s2n_drbg_bits(struct s2n_drbg *drbg, struct s2n_blob *out)
{
    notnull_check(drbg);
    notnull_check(drbg->ctx);
    notnull_check(out);

    struct s2n_blob value = {0};
    GUARD(s2n_blob_init(&value, drbg->v, sizeof(drbg->v)));
    int block_aligned_size = out->size - (out->size % S2N_DRBG_BLOCK_SIZE);

    /* Per NIST SP800-90A 10.2.1.2: */
    for (int i = 0; i < block_aligned_size; i += S2N_DRBG_BLOCK_SIZE) {
        GUARD(s2n_increment_drbg_counter(&value));
        GUARD(s2n_drbg_block_encrypt(drbg->ctx, drbg->v, out->data + i));
        drbg->bytes_used += S2N_DRBG_BLOCK_SIZE;
    }

    if (out->size <= block_aligned_size) {
        return 0;
    }

    uint8_t spare_block[S2N_DRBG_BLOCK_SIZE];
    GUARD(s2n_increment_drbg_counter(&value));
    GUARD(s2n_drbg_block_encrypt(drbg->ctx, drbg->v, spare_block));
    drbg->bytes_used += S2N_DRBG_BLOCK_SIZE;

    memcpy_check(out->data + block_aligned_size, spare_block, out->size - block_aligned_size);

    return 0;
}

static int s2n_drbg_update(struct s2n_drbg *drbg, struct s2n_blob *provided_data)
{
    notnull_check(drbg);
    notnull_check(drbg->ctx);

    s2n_stack_blob(temp_blob, s2n_drbg_seed_size(drgb), S2N_DRBG_MAX_SEED_SIZE);

    eq_check(provided_data->size, s2n_drbg_seed_size(drbg));

    GUARD(s2n_drbg_bits(drbg, &temp_blob));

    /* XOR in the provided data */
    for (int i = 0; i < provided_data->size; i++) {
        temp_blob.data[i] ^= provided_data->data[i];
    }

    /* Update the key and value */
    GUARD_OSSL(EVP_EncryptInit_ex(drbg->ctx, NULL, NULL, temp_blob.data, NULL), S2N_ERR_DRBG);

    memcpy_check(drbg->v, temp_blob.data + s2n_drbg_key_size(drbg), S2N_DRBG_BLOCK_SIZE);

    return 0;
}

static int s2n_drbg_seed(struct s2n_drbg *drbg, struct s2n_blob *ps)
{
    notnull_check(drbg);
    notnull_check(drbg->ctx);
    s2n_stack_blob(blob, s2n_drbg_seed_size(drbg), S2N_DRBG_MAX_SEED_SIZE);

    if (drbg->entropy_generator) {
        GUARD(drbg->entropy_generator(&blob));
    } else {
        GUARD(s2n_get_urandom_data(&blob));
    }

    for (int i = 0; i < ps->size; i++) {
        blob.data[i] ^= ps->data[i];
    }

    GUARD(s2n_drbg_update(drbg, &blob));

    drbg->bytes_used = 0;
    drbg->generation += 1;

    return 0;
}

int s2n_drbg_instantiate(struct s2n_drbg *drbg, struct s2n_blob *personalization_string, const s2n_drbg_mode mode)
{
    notnull_check(drbg);
    S2N_ERROR_IF(mode == S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR && !s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    S2N_ERROR_IF(drbg->entropy_generator != NULL && !s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);

    if (mode == S2N_AES_128_CTR_NO_DF_PR || mode == S2N_AES_256_CTR_NO_DF_PR) {
        drbg->use_prediction_resistance = 1;
    } else if ( mode == S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR) {
        drbg->use_prediction_resistance = 0;
    } else {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    drbg->ctx = EVP_CIPHER_CTX_new();
    S2N_ERROR_IF(!drbg->ctx, S2N_ERR_DRBG);

    s2n_evp_ctx_init(drbg->ctx);

    if (mode == S2N_AES_128_CTR_NO_DF_PR) {
        GUARD_OSSL(EVP_EncryptInit_ex(drbg->ctx, EVP_aes_128_ecb(), NULL, NULL, NULL), S2N_ERR_DRBG);
    } else if (mode == S2N_AES_256_CTR_NO_DF_PR || mode == S2N_DANGEROUS_AES_256_CTR_NO_DF_NO_PR) {
        GUARD_OSSL(EVP_EncryptInit_ex(drbg->ctx, EVP_aes_256_ecb(), NULL, NULL, NULL), S2N_ERR_DRBG);
    } else {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    lte_check(s2n_drbg_key_size(drbg), S2N_DRBG_MAX_KEY_SIZE);
    lte_check(s2n_drbg_seed_size(drbg), S2N_DRBG_MAX_SEED_SIZE);

    static const uint8_t zero_key[S2N_DRBG_MAX_KEY_SIZE] = {0};

    /* Start off with zeroed data, per 10.2.1.3.1 item 4 and 5 */
    memset(drbg->v, 0, sizeof(drbg->v));
    GUARD_OSSL(EVP_EncryptInit_ex(drbg->ctx, NULL, NULL, zero_key, NULL), S2N_ERR_DRBG);

    /* Copy the personalization string */
    s2n_stack_blob(ps, s2n_drbg_seed_size(drbg), S2N_DRBG_MAX_SEED_SIZE);
    GUARD(s2n_blob_zero(&ps));

    memcpy_check(ps.data, personalization_string->data, MIN(ps.size, personalization_string->size));

    /* Seed / update the DRBG */
    GUARD(s2n_drbg_seed(drbg, &ps));

    /* After initial seeding, pivot to RDRAND if available and not overridden */
    if (drbg->entropy_generator == NULL && s2n_cpu_supports_rdrand()) {
        drbg->entropy_generator = s2n_get_rdrand_data;
    }

    return 0;
}

int s2n_drbg_generate(struct s2n_drbg *drbg, struct s2n_blob *blob)
{
    notnull_check(drbg);
    notnull_check(drbg->ctx);
    s2n_stack_blob(zeros, s2n_drbg_seed_size(drbg), S2N_DRBG_MAX_SEED_SIZE);

    S2N_ERROR_IF(blob->size > S2N_DRBG_GENERATE_LIMIT, S2N_ERR_DRBG_REQUEST_SIZE);

    /* If either use_prediction_resistance is set, or if we reach the definitely-need-to-reseed limit, then reseed */
    if (drbg->use_prediction_resistance || drbg->bytes_used + blob->size + S2N_DRBG_BLOCK_SIZE >= S2N_DRBG_RESEED_LIMIT) {
        GUARD(s2n_drbg_seed(drbg, &zeros));
    } else if (!drbg->use_prediction_resistance && !s2n_in_unit_test()) {
        S2N_ERROR(S2N_ERR_NOT_IN_UNIT_TEST);
    }

    GUARD(s2n_drbg_bits(drbg, blob));
    GUARD(s2n_drbg_update(drbg, &zeros));

    return 0;
}

int s2n_drbg_wipe(struct s2n_drbg *drbg)
{
    notnull_check(drbg);
    if (drbg->ctx) {
        GUARD_OSSL(EVP_CIPHER_CTX_cleanup(drbg->ctx), S2N_ERR_DRBG);

        EVP_CIPHER_CTX_free(drbg->ctx);
        drbg->ctx = NULL;
    }

    *drbg = (struct s2n_drbg) {0};
    return 0;
}

int s2n_drbg_bytes_used(struct s2n_drbg *drbg)
{
    notnull_check(drbg);
    return drbg->bytes_used;
}
