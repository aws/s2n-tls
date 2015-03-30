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

#include <openssl/evp.h>

#include "crypto/s2n_sequence.h"
#include "crypto/s2n_drbg.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

static int s2n_drbg_block_encrypt(EVP_CIPHER_CTX *ctx, uint8_t in[S2N_DRBG_BLOCK_SIZE], uint8_t out[S2N_DRBG_BLOCK_SIZE])
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
    int block_aligned_size = out->size - (out->size % S2N_DRBG_BLOCK_SIZE);

    /* Per NIST SP800-90A 10.2.1.2: */
    for (int i = 0; i < block_aligned_size; i += S2N_DRBG_BLOCK_SIZE) {
        GUARD(s2n_increment_sequence_number(&drbg->value));
        GUARD(s2n_drbg_block_encrypt(&drbg->ctx, drbg->v, out->data + i));
    }

    if (out->size <= block_aligned_size) {
        return 0;
    }

    uint8_t spare_block[S2N_DRBG_BLOCK_SIZE];
    GUARD(s2n_increment_sequence_number(&drbg->value));
    GUARD(s2n_drbg_block_encrypt(&drbg->ctx, drbg->v, spare_block));

    memcpy_check(out->data + block_aligned_size, spare_block, out->size - block_aligned_size);

    return 0;
}

static int s2n_drbg_update(struct s2n_drbg *drbg, struct s2n_blob *provided_data)
{
    uint8_t temp[32];
    struct s2n_blob temp_blob = {.data = temp, .size = sizeof(temp) };

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

int s2n_drbg_seed(struct s2n_drbg *drbg, struct s2n_blob *personalization_string)
{
    uint8_t seed[32];
    struct s2n_blob blob = {.data = seed, .size = sizeof(seed) };

    if (!drbg->entropy_generator) {
        GUARD(s2n_get_urandom_data(&blob));
    }
    else {
        GUARD(drbg->entropy_generator(&blob));
    }

    for (int i = 0; i < personalization_string->size && i < blob.size; i++) {
        blob.data[i] ^= personalization_string->data[i];
    }

    GUARD(s2n_drbg_update(drbg, &blob));

    drbg->bytes_used = 0;
    drbg->generation += 1;

    return 0;
}

int s2n_drbg_instantiate(struct s2n_drbg *drbg, struct s2n_blob *personalization_string)
{
    drbg->value.size = sizeof(drbg->v);
    drbg->value.data = drbg->v;

    /* Start off with zerod data, per 10.2.1.3.1 item 4 */
    memset_check(drbg->v, 0, sizeof(drbg->v));

    /* Start off with zerod key, per 10.2.1.3.1 item 5 */
    (void) EVP_CIPHER_CTX_init(&drbg->ctx);
    if (EVP_EncryptInit_ex(&drbg->ctx, EVP_aes_128_ecb(), NULL, drbg->v, NULL) != 1) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    /* Seed / update the DRBG */
    GUARD(s2n_drbg_seed(drbg, personalization_string));

    return 0;
}

int s2n_drbg_generate(struct s2n_drbg *drbg, struct s2n_blob *blob)
{
    uint8_t all_zeros[32] = { 0 };
    struct s2n_blob zeros = {.data = all_zeros, .size = sizeof(all_zeros) };
    if (blob->size > S2N_DRBG_GENERATE_LIMIT) {
        S2N_ERROR(S2N_ERR_DRBG_REQUEST_SIZE);
    }

    if (drbg->bytes_used + blob->size + S2N_DRBG_BLOCK_SIZE >= S2N_DRBG_RESEED_LIMIT) {
        struct s2n_blob ps = {.size = 0 };
        GUARD(s2n_drbg_seed(drbg, &ps));
    }

    GUARD(s2n_drbg_bits(drbg, blob));
    GUARD(s2n_drbg_update(drbg, &zeros));

    return 0;
}

int s2n_drbg_wipe(struct s2n_drbg *drbg)
{
    struct s2n_blob state = {.data = (void *) drbg, .size = sizeof(struct s2n_drbg) };

    if (EVP_CIPHER_CTX_cleanup(&drbg->ctx) != 1) {
         S2N_ERROR(S2N_ERR_DRBG);
    }

    GUARD(s2n_blob_zero(&state));

    return 0;
}
