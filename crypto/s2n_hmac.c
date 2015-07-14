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

#include <openssl/md5.h>
#include <openssl/sha.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

int s2n_hmac_digest_size(s2n_hmac_algorithm alg)
{
    if (alg == S2N_HMAC_SSLv3_MD5) {
        alg = S2N_HMAC_MD5;
    }
    if (alg == S2N_HMAC_SSLv3_SHA1) {
        alg = S2N_HMAC_SHA1;
    }

    return s2n_hash_digest_size((s2n_hash_algorithm) alg);
}

static int s2n_sslv3_mac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    s2n_hash_algorithm hash_alg = S2N_HASH_NONE;

    if (alg == S2N_HMAC_SSLv3_MD5) {
        hash_alg = S2N_HASH_MD5;
    }
    if (alg == S2N_HMAC_SSLv3_SHA1) {
        hash_alg = S2N_HASH_SHA1;
    }

    for (int i = 0; i < state->block_size; i++) {
        state->xor_pad[i] = 0x36;
    }

    GUARD(s2n_hash_init(&state->inner_just_key, hash_alg));
    GUARD(s2n_hash_update(&state->inner_just_key, key, klen));
    GUARD(s2n_hash_update(&state->inner_just_key, state->xor_pad, state->block_size));

    for (int i = 0; i < state->block_size; i++) {
        state->xor_pad[i] = 0x5c;
    }

    GUARD(s2n_hash_init(&state->outer, hash_alg));
    GUARD(s2n_hash_update(&state->outer, key, klen));
    GUARD(s2n_hash_update(&state->outer, state->xor_pad, state->block_size));

    /* Copy inner_just_key to inner */
    return s2n_hmac_reset(state);
}

static int s2n_sslv3_mac_digest(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    for (int i = 0; i < state->block_size; i++) {
        state->xor_pad[i] = 0x5c;
    }

    GUARD(s2n_hash_digest(&state->inner, state->digest_pad, state->digest_size));
    memcpy_check(&state->inner, &state->outer, sizeof(state->inner));
    GUARD(s2n_hash_update(&state->inner, state->digest_pad, state->digest_size));

    return s2n_hash_digest(&state->inner, out, size);
}

int s2n_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    s2n_hash_algorithm hash_alg = S2N_HASH_NONE;
    state->digest_size = 0;
    state->block_size = 64;

    switch (alg) {
    case S2N_HMAC_NONE:
        break;
    case S2N_HMAC_SSLv3_MD5:
        state->block_size = 48;
        /* Fall through ... */
    case S2N_HMAC_MD5:
        hash_alg = S2N_HASH_MD5;
        state->digest_size = MD5_DIGEST_LENGTH;
        break;
    case S2N_HMAC_SSLv3_SHA1:
        state->block_size = 40;
        /* Fall through ... */
    case S2N_HMAC_SHA1:
        hash_alg = S2N_HASH_SHA1;
        state->digest_size = SHA_DIGEST_LENGTH;
        break;
    case S2N_HMAC_SHA224:
        hash_alg = S2N_HASH_SHA224;
        state->digest_size = SHA224_DIGEST_LENGTH;
        break;
    case S2N_HMAC_SHA256:
        hash_alg = S2N_HASH_SHA256;
        state->digest_size = SHA256_DIGEST_LENGTH;
        break;
    case S2N_HMAC_SHA384:
        hash_alg = S2N_HASH_SHA384;
        state->digest_size = SHA384_DIGEST_LENGTH;
        state->block_size = 128;
        break;
    case S2N_HMAC_SHA512:
        hash_alg = S2N_HASH_SHA512;
        state->digest_size = SHA512_DIGEST_LENGTH;
        state->block_size = 128;
        break;
    default:
        S2N_ERROR(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }

    gte_check(sizeof(state->xor_pad), state->block_size);
    gte_check(sizeof(state->digest_pad), state->digest_size);

    state->alg = alg;

    if (alg == S2N_HMAC_SSLv3_SHA1 || alg == S2N_HMAC_SSLv3_MD5) {
        return s2n_sslv3_mac_init(state, alg, key, klen);
    }

    GUARD(s2n_hash_init(&state->inner_just_key, hash_alg));
    GUARD(s2n_hash_init(&state->outer, hash_alg));

    uint32_t copied = klen;
    if (klen > state->block_size) {
        GUARD(s2n_hash_update(&state->outer, key, klen));
        GUARD(s2n_hash_digest(&state->outer, state->digest_pad, state->digest_size));

        memcpy_check(state->xor_pad, state->digest_pad, state->digest_size);
        copied = state->digest_size;
    } else {
        memcpy_check(state->xor_pad, key, klen);
    }

    for (int i = 0; i < copied; i++) {
        state->xor_pad[i] ^= 0x36;
    }
    for (int i = copied; i < state->block_size; i++) {
        state->xor_pad[i] = 0x36;
    }

    GUARD(s2n_hash_update(&state->inner_just_key, state->xor_pad, state->block_size));

    /* 0x36 xor 0x5c == 0x6a */
    for (int i = 0; i < state->block_size; i++) {
        state->xor_pad[i] ^= 0x6a;
    }

    return s2n_hmac_reset(state);
}

int s2n_hmac_update(struct s2n_hmac_state *state, const void *in, uint32_t size)
{
    return s2n_hash_update(&state->inner, in, size);
}

int s2n_hmac_digest(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    if (state->alg == S2N_HMAC_SSLv3_SHA1 || state->alg == S2N_HMAC_SSLv3_MD5) {
        return s2n_sslv3_mac_digest(state, out, size);
    }

    GUARD(s2n_hash_digest(&state->inner, state->digest_pad, state->digest_size));
    GUARD(s2n_hash_reset(&state->outer));
    GUARD(s2n_hash_update(&state->outer, state->xor_pad, state->block_size));
    GUARD(s2n_hash_update(&state->outer, state->digest_pad, state->digest_size));

    return s2n_hash_digest(&state->outer, out, size);
}

int s2n_hmac_reset(struct s2n_hmac_state *state)
{
    memcpy_check(&state->inner, &state->inner_just_key, sizeof(state->inner));

    return 0;
}

int s2n_hmac_digest_verify(const void *a, const void *b, uint32_t len)
{
    return 0 - !s2n_constant_time_equals(a, b, len);
}

int s2n_hmac_copy(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    memcpy_check(to, from, sizeof(struct s2n_hmac_state));
    return 0;
}
