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

#include <stdio.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hmac.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#define MAX_DIGEST_SIZE 64      /* Current highest is SHA512 */
#define MAX_HKDF_ROUNDS 255

/* Reference: RFC 5869 */

int s2n_hkdf_extract(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const struct s2n_blob *salt,
                     const struct s2n_blob *key, struct s2n_blob *pseudo_rand_key)
{
    uint8_t hmac_size;
    POSIX_GUARD(s2n_hmac_digest_size(alg, &hmac_size));
    pseudo_rand_key->size = hmac_size;
    POSIX_GUARD(s2n_hmac_init(hmac, alg, salt->data, salt->size));
    POSIX_GUARD(s2n_hmac_update(hmac, key->data, key->size));
    POSIX_GUARD(s2n_hmac_digest(hmac, pseudo_rand_key->data, pseudo_rand_key->size));

    POSIX_GUARD(s2n_hmac_reset(hmac));

    return 0;
}

static int s2n_hkdf_expand(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const struct s2n_blob *pseudo_rand_key,
                           const struct s2n_blob *info, struct s2n_blob *output)
{
    uint8_t prev[MAX_DIGEST_SIZE] = { 0 };

    uint32_t done_len = 0;
    uint8_t hash_len;
    POSIX_GUARD(s2n_hmac_digest_size(alg, &hash_len));
    uint32_t total_rounds = output->size / hash_len;
    if (output->size % hash_len) {
        total_rounds++;
    }

    S2N_ERROR_IF(total_rounds > MAX_HKDF_ROUNDS || total_rounds == 0, S2N_ERR_HKDF_OUTPUT_SIZE);

    for (uint32_t curr_round = 1; curr_round <= total_rounds; curr_round++) {
        uint32_t cat_len;
        POSIX_GUARD(s2n_hmac_init(hmac, alg, pseudo_rand_key->data, pseudo_rand_key->size));
        if (curr_round != 1) {
            POSIX_GUARD(s2n_hmac_update(hmac, prev, hash_len));
        }
        POSIX_GUARD(s2n_hmac_update(hmac, info->data, info->size));
        POSIX_GUARD(s2n_hmac_update(hmac, &curr_round, 1));
        POSIX_GUARD(s2n_hmac_digest(hmac, prev, hash_len));

        cat_len = hash_len;
        if (done_len + hash_len > output->size) {
            cat_len = output->size - done_len;
        }

        POSIX_CHECKED_MEMCPY(output->data + done_len, prev, cat_len);

        done_len += cat_len;
    
        POSIX_GUARD(s2n_hmac_reset(hmac));
    }

    return 0;
}

int s2n_hkdf_expand_label(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const struct s2n_blob *secret, const struct s2n_blob *label,
                          const struct s2n_blob *context, struct s2n_blob *output)
{
    /* Per RFC8446: 7.1, a HKDF label is a 2 byte length field, and two 1...255 byte arrays with a one byte length field each. */
    uint8_t hkdf_label_buf[2 + 256 + 256];
    struct s2n_blob hkdf_label_blob = {0};
    struct s2n_stuffer hkdf_label = {0};

    /* RFC8446 specifies that labels must be 12 characters or less, to avoid
    ** incurring two hash rounds.
    */
    POSIX_ENSURE_LTE(label->size, 12);

    POSIX_GUARD(s2n_blob_init(&hkdf_label_blob, hkdf_label_buf, sizeof(hkdf_label_buf)));
    POSIX_GUARD(s2n_stuffer_init(&hkdf_label, &hkdf_label_blob));
    POSIX_GUARD(s2n_stuffer_write_uint16(&hkdf_label, output->size));
    POSIX_GUARD(s2n_stuffer_write_uint8(&hkdf_label, label->size + sizeof("tls13 ") - 1));
    POSIX_GUARD(s2n_stuffer_write_str(&hkdf_label, "tls13 "));
    POSIX_GUARD(s2n_stuffer_write(&hkdf_label, label));
    POSIX_GUARD(s2n_stuffer_write_uint8(&hkdf_label, context->size));
    POSIX_GUARD(s2n_stuffer_write(&hkdf_label, context));

    hkdf_label_blob.size = s2n_stuffer_data_available(&hkdf_label);
    POSIX_GUARD(s2n_hkdf_expand(hmac, alg, secret, &hkdf_label_blob, output));

    return 0;
}

int s2n_hkdf(struct s2n_hmac_state *hmac, s2n_hmac_algorithm alg, const struct s2n_blob *salt,
             const struct s2n_blob *key, const struct s2n_blob *info, struct s2n_blob *output)
{
    uint8_t prk_pad[MAX_DIGEST_SIZE];
    struct s2n_blob pseudo_rand_key = {.data = prk_pad,.size = sizeof(prk_pad) };

    POSIX_GUARD(s2n_hkdf_extract(hmac, alg, salt, key, &pseudo_rand_key));
    POSIX_GUARD(s2n_hkdf_expand(hmac, alg, &pseudo_rand_key, info, output));

    return 0;
}
