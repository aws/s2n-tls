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

#include <openssl/evp.h>

#include "crypto/s2n_drbg.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_blob.h"

static int s2n_drbg_init(struct s2n_drbg *drbg)
{
    if (drbg->initialized) {
        return 0;
    }

    EVP_CIPHER_CTX_init(&drbg->evp_cipher_ctx);
    EVP_CIPHER_CTX_set_padding(&drbg->evp_cipher_ctx, EVP_CIPH_NO_PADDING);

    drbg->initialized = 1;

    return 0;
}

static int s2n_drbg_replenish_cache(struct s2n_drbg *drbg)
{
    uint8_t all_zeros[ sizeof(drbg->cache) ] = { 0 };
    int len = sizeof(drbg->cache);

    if (EVP_EncryptUpdate(&drbg->evp_cipher_ctx, drbg->cache, &len, all_zeros, sizeof(drbg->cache)) == 0) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    if (len != sizeof(drbg->cache)) {
        S2N_ERROR(S2N_ERR_DRBG);
    }

    drbg->cache_remaining = sizeof(drbg->cache);
    drbg->bytes_used += sizeof(drbg->cache);

    return 0;
}

int s2n_drbg_seed(struct s2n_drbg *drbg)
{
    uint8_t seed[48];
    struct s2n_blob blob = {.data = seed, .size = sizeof(seed) };

    GUARD(s2n_drbg_init(drbg));

    GUARD(s2n_get_urandom_data(&blob));

    EVP_EncryptInit_ex(&drbg->evp_cipher_ctx, EVP_aes_256_ctr(), NULL, seed, seed + 32);

    drbg->bytes_used = 0;
    drbg->cache_remaining = 0;
    drbg->generation += 1;

    return 0;
}

int s2n_drbg_generate(struct s2n_drbg *drbg, struct s2n_blob *blob)
{
    uint8_t *bytes_out = blob->data;
    uint32_t bytes_needed = blob->size;

    if (!drbg->initialized) {
        GUARD(s2n_drbg_seed(drbg));
    }

    while(bytes_needed) {
        if (drbg->bytes_used + sizeof(drbg->cache) > S2N_DRBG_RESEED_LIMIT) {
            drbg->bytes_used = 0;
            GUARD(s2n_drbg_seed(drbg));
        }

        if (drbg->cache_remaining == 0) {
            GUARD(s2n_drbg_replenish_cache(drbg));
        }

        uint32_t bytes_generated = bytes_needed;
        if (bytes_generated > drbg->cache_remaining) {
            bytes_generated = drbg->cache_remaining;
        }

        memcpy_check(bytes_out, drbg->cache, bytes_generated);

        drbg->cache_remaining -= bytes_generated;
        bytes_needed -= bytes_generated;
        bytes_out += bytes_generated;
    }

    return 0;
}
