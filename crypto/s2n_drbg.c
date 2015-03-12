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

static int s2n_drbg_bits(struct s2n_drbg *drbg, struct s2n_blob *out)
{
    int block_aligned_size = out->size - (out->size % 16);

    /* Per NIST SP800-90A 10.2.1.2: */
    for (int i = 0; i < block_aligned_size; i += 16) {
        GUARD(s2n_increment_sequence_number(&drbg->value));

        int len = 16;
        if (EVP_EncryptUpdate(&drbg->evp_cipher_ctx, out->data + i, &len, drbg->value.data, drbg->value.size) == 0) {
            S2N_ERROR(S2N_ERR_DRBG);
        }
        if (len != 16) {
            S2N_ERROR(S2N_ERR_DRBG);
        }
    }

    if (out->size <= block_aligned_size) {
        return 0;
    }

    uint8_t spare_block[16];
    struct s2n_blob spare = {.data = spare_block, .size = 16};

    /* Recurse to get the spare block */
    GUARD(s2n_drbg_bits(drbg, &spare));

    memcpy_check(out->data + block_aligned_size, spare_block, out->size - block_aligned_size);

    return 0;
}

static int s2n_drbg_update(struct s2n_drbg *drbg, struct s2n_blob *provided_data)
{
    uint8_t temp[32];
    struct s2n_blob temp_blob = {.data = temp, .size = sizeof(temp) };

    eq_check(provided_data->size, sizeof(temp));

    /* Per NIST SP800-90A 10.2.1.2: */
    GUARD(s2n_drbg_bits(drbg, &temp_blob));

    /* XOR in the provided data */
    for (int i = 0; i < provided_data->size && i < 32; i++) {
        temp[i] ^= provided_data->data[i];
    }

    /* Update the key we use */
    if (EVP_EncryptInit(&drbg->evp_cipher_ctx, EVP_aes_128_ecb(), temp, NULL) == 0) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    /* Update the value we use */
    memcpy_check(drbg->value.data, temp + 16, drbg->value.size);

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
    EVP_CIPHER_CTX_init(&drbg->evp_cipher_ctx);
    EVP_CIPHER_CTX_set_padding(&drbg->evp_cipher_ctx, EVP_CIPH_NO_PADDING);

    /* Start off with zerod data, per 10.2.1.3.1 item 4 */
    drbg->value.size = sizeof(drbg->value_data);
    drbg->value.data = drbg->value_data;
    memset_check(drbg->value.data, 0, drbg->value.size);

    /* Start off with zerod key, per 10.2.1.3.1 item 5 */
    if (EVP_EncryptInit(&drbg->evp_cipher_ctx, EVP_aes_128_ctr(), drbg->value.data, NULL) == 0) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    /* Seed / update the DRBG */
    GUARD(s2n_drbg_seed(drbg, personalization_string));

    return 0;
}

int s2n_drbg_generate(struct s2n_drbg *drbg, struct s2n_blob *blob)
{
    if (blob->size > S2N_DRBG_GENERATE_LIMIT) {
        S2N_ERROR(S2N_ERR_DRBG_REQUEST_SIZE);
    }

    if (drbg->bytes_used + blob->size + 16 >= S2N_DRBG_RESEED_LIMIT) {
        struct s2n_blob ps = {.size = 0 };
        GUARD(s2n_drbg_seed(drbg, &ps));
    }

    GUARD(s2n_drbg_bits(drbg, blob));

    return 0;
}
