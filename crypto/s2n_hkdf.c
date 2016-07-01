/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdio.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_hmac.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#define MAX_DIGEST_SIZE 64 /*current highest is SHA512*/

//Reference: RFC 5869

int s2n_hkdf_extract(s2n_hmac_algorithm alg,
                     const struct s2n_blob *salt,
                     const struct s2n_blob *key,
                     struct s2n_blob *pseudo_rand_key)
{
    struct s2n_hmac_state hmac;
    pseudo_rand_key->size = s2n_hmac_digest_size(alg);

    GUARD(s2n_hmac_init(&hmac, alg, salt->data, salt->size));
    GUARD(s2n_hmac_update(&hmac, key->data, key->size));
    GUARD(s2n_hmac_digest(&hmac, pseudo_rand_key->data, pseudo_rand_key->size));

    return 0;
}

int s2n_hkdf_expand(s2n_hmac_algorithm alg,
                    const struct s2n_blob *pseudo_rand_key,
                    const struct s2n_blob *info,
                    struct s2n_blob *out_key)
{
    uint8_t prev[MAX_DIGEST_SIZE] = "";

    uint32_t done_len = 0;
    uint32_t hash_len = s2n_hmac_digest_size(alg);
    uint32_t total_rounds = out_key->size / hash_len;
    if(out_key->size % hash_len)
        total_rounds++;

    if(total_rounds > 255)
        return -1;

    struct s2n_hmac_state hmac;

    uint32_t cat_len;
    for(uint32_t curr_round = 1; curr_round <= total_rounds; curr_round++){
 
        GUARD(s2n_hmac_init(&hmac, alg, pseudo_rand_key->data, pseudo_rand_key->size));
        if(curr_round!=1)
            GUARD(s2n_hmac_update(&hmac, prev, hash_len));
        GUARD(s2n_hmac_update(&hmac, info->data, info->size));
        GUARD(s2n_hmac_update(&hmac, &curr_round, 1));
        GUARD(s2n_hmac_digest(&hmac, prev, hash_len));

        cat_len = hash_len;
        if(done_len + hash_len > out_key->size)
            cat_len = out_key->size - done_len;

        memcpy_check(out_key->data + done_len, prev, cat_len);

        done_len += cat_len;
    }

    return 0;
}

int s2n_hkdf(s2n_hmac_algorithm alg,
             const struct s2n_blob *salt, const struct s2n_blob *key,
             const struct s2n_blob *info, struct s2n_blob *out_key)
{
    uint8_t prk_pad[MAX_DIGEST_SIZE];
    struct s2n_blob pseudo_rand_key = {.data = prk_pad, .size = sizeof(prk_pad) };

    GUARD(s2n_hkdf_extract(alg, salt, key, &pseudo_rand_key));
    GUARD(s2n_hkdf_expand(alg, &pseudo_rand_key, info, out_key));

    return 0;
}
