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

#include "crypto/s2n_sequence.h"
#include "crypto/s2n_drbg.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

static int s2n_drbg_block_encrypt(EVP_CIPHER_CTX * ctx, uint8_t in[S2N_DRBG_BLOCK_SIZE], uint8_t out[S2N_DRBG_BLOCK_SIZE])
{
    int len = S2N_DRBG_BLOCK_SIZE;
    if (EVP_EncryptUpdate(ctx, out, &len, in, S2N_DRBG_BLOCK_SIZE) != 1) {
        S2N_ERROR(S2N_ERR_DRBG);
    }
    eq_check(len, S2N_DRBG_BLOCK_SIZE);

    return 0;
}

static int s2n_drbg_bits(struct s2n_drbg *drbg, struct s2n_blob *out)
{
    struct s2n_blob value = {.data = drbg->v,.size = sizeof(drbg->v) };
    int block_aligned_size = out->size - (out->size % S2N_DRBG_BLOCK_SIZE);

    /* Per NIST SP800-90A 10.2.1.2: */
    for (int i = 0; i < block_aligned_size; i += S2N_DRBG_BLOCK_SIZE) {
        GUARD(s2n_increment_sequence_number(&value));
        GUARD(s2n_drbg_block_encrypt(&drbg->ctx, drbg->v, out->data + i));
        drbg->bytes_used += S2N_DRBG_BLOCK_SIZE;
    }

    if (out->size <= block_aligned_size) {
        return 0;
    }

    uint8_t spare_block[S2N_DRBG_BLOCK_SIZE];
    GUARD(s2n_increment_sequence_number(&value));
    GUARD(s2n_drbg_block_encrypt(&drbg->ctx, drbg->v, spare_block));
    drbg->bytes_used += S2N_DRBG_BLOCK_SIZE;

    memcpy_check(out->data + block_aligned_size, spare_block, out->size - block_aligned_size);

    return 0;
}

static int s2n_drbg_update(struct s2n_drbg *drbg, struct s2n_blob *provided_data)
{
    uint8_t temp[32];
    struct s2n_blob temp_blob = {.data = temp,.size = sizeof(temp) };

    eq_check(provided_data->size, sizeof(temp));

    GUARD(s2n_drbg_bits(drbg, &temp_blob));

    /* XOR in the provided data */
    for (int i = 0; i < provided_data->size; i++) {
        temp[i] ^= provided_data->data[i];
    }

    /* Update the key and value */
    if (EVP_EncryptInit_ex(&drbg->ctx, EVP_aes_128_ecb(), NULL, temp, NULL) != 1) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    memcpy_check(drbg->v, temp + S2N_DRBG_BLOCK_SIZE, S2N_DRBG_BLOCK_SIZE);

    return 0;
}

int s2n_drbg_seed(struct s2n_drbg *drbg, struct s2n_blob *ps)
{
    uint8_t seed[32];
    struct s2n_blob blob = {.data = seed,.size = sizeof(seed) };
    lte_check(ps->size, sizeof(seed));

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

int s2n_drbg_instantiate(struct s2n_drbg *drbg, struct s2n_blob *personalization_string)
{
    struct s2n_blob value = {.data = drbg->v,.size = sizeof(drbg->v) };
    uint8_t ps_prefix[32];
    struct s2n_blob ps = {.data = ps_prefix,.size = sizeof(ps_prefix) };

    /* Start off with zerod data, per 10.2.1.3.1 item 4 */
    GUARD(s2n_blob_zero(&value));

    /* Start off with zerod key, per 10.2.1.3.1 item 5 */
    (void)EVP_CIPHER_CTX_init(&drbg->ctx);
    if (EVP_EncryptInit_ex(&drbg->ctx, EVP_aes_128_ecb(), NULL, drbg->v, NULL) != 1) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    /* Copy the personalization string */
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
    uint8_t all_zeros[32] = { 0 };
    struct s2n_blob zeros = {.data = all_zeros,.size = sizeof(all_zeros) };
    if (blob->size > S2N_DRBG_GENERATE_LIMIT) {
        S2N_ERROR(S2N_ERR_DRBG_REQUEST_SIZE);
    }

    /* If either the entropy generator is set, for prediction resistance,
     * or if we reach the definitely-need-to-reseed limit, then reseed.
     */
    if (drbg->entropy_generator || drbg->bytes_used + blob->size + S2N_DRBG_BLOCK_SIZE >= S2N_DRBG_RESEED_LIMIT) {
        GUARD(s2n_drbg_seed(drbg, &zeros));
    }

    GUARD(s2n_drbg_bits(drbg, blob));
    GUARD(s2n_drbg_update(drbg, &zeros));

    return 0;
}

int s2n_drbg_wipe(struct s2n_drbg *drbg)
{
    struct s2n_blob state = {.data = (void *)drbg,.size = sizeof(struct s2n_drbg) };

    if (EVP_CIPHER_CTX_cleanup(&drbg->ctx) != 1) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    GUARD(s2n_blob_zero(&state));

    return 0;
}

int s2n_drbg_bytes_used(struct s2n_drbg *drbg)
{
    return drbg->bytes_used;
}
