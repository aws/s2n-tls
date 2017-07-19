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

int s2n_hmac_hash_alg(s2n_hmac_algorithm hmac_alg, s2n_hash_algorithm *out)
{
    switch(hmac_alg) {
    case S2N_HMAC_NONE:       *out = S2N_HASH_NONE;   break;
    case S2N_HMAC_MD5:        *out = S2N_HASH_MD5;    break;
    case S2N_HMAC_SHA1:       *out = S2N_HASH_SHA1;   break;
    case S2N_HMAC_SHA224:     *out = S2N_HASH_SHA224; break;
    case S2N_HMAC_SHA256:     *out = S2N_HASH_SHA256; break;
    case S2N_HMAC_SHA384:     *out = S2N_HASH_SHA384; break;
    case S2N_HMAC_SHA512:     *out = S2N_HASH_SHA512; break;
    case S2N_HMAC_SSLv3_MD5:  *out = S2N_HASH_MD5;    break;
    case S2N_HMAC_SSLv3_SHA1: *out = S2N_HASH_SHA1;   break;
    default:
        S2N_ERROR(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }
    return 0;
}



int s2n_hmac_digest_size(s2n_hmac_algorithm hmac_alg, uint8_t *out)
{
    s2n_hash_algorithm hash_alg;
    GUARD(s2n_hmac_hash_alg(hmac_alg, &hash_alg));
    GUARD(s2n_hash_digest_size(hash_alg, out));
    return 0;
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
    GUARD(s2n_hash_copy(&state->inner, &state->outer));
    GUARD(s2n_hash_update(&state->inner, state->digest_pad, state->digest_size));

    return s2n_hash_digest(&state->inner, out, size);
}

int s2n_hmac_block_size(s2n_hmac_algorithm hmac_alg, uint16_t *block_size)
{
    switch(hmac_alg) {
    case S2N_HMAC_NONE:       *block_size = 64;   break;
    case S2N_HMAC_MD5:        *block_size = 64;   break;
    case S2N_HMAC_SHA1:       *block_size = 64;   break;
    case S2N_HMAC_SHA224:     *block_size = 64;   break;
    case S2N_HMAC_SHA256:     *block_size = 64;   break;
    case S2N_HMAC_SHA384:     *block_size = 128;  break;
    case S2N_HMAC_SHA512:     *block_size = 128;  break;
    case S2N_HMAC_SSLv3_MD5:  *block_size = 48;   break;
    case S2N_HMAC_SSLv3_SHA1: *block_size = 40;   break;
    default:
        S2N_ERROR(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }
    return 0;
}

int s2n_hmac_hash_block_size(s2n_hmac_algorithm hmac_alg, uint16_t *block_size)
{
    switch(hmac_alg) {
    case S2N_HMAC_NONE:       *block_size = 64;   break;
    case S2N_HMAC_MD5:        *block_size = 64;   break;
    case S2N_HMAC_SHA1:       *block_size = 64;   break;
    case S2N_HMAC_SHA224:     *block_size = 64;   break;
    case S2N_HMAC_SHA256:     *block_size = 64;   break;
    case S2N_HMAC_SHA384:     *block_size = 128;  break;
    case S2N_HMAC_SHA512:     *block_size = 128;  break;
    case S2N_HMAC_SSLv3_MD5:  *block_size = 64;   break;
    case S2N_HMAC_SSLv3_SHA1: *block_size = 64;   break;
    default:
        S2N_ERROR(S2N_ERR_HMAC_INVALID_ALGORITHM);
    }
    return 0;
}

int s2n_hmac_new(struct s2n_hmac_state *state)
{
    GUARD(s2n_hash_new(&state->inner));
    GUARD(s2n_hash_new(&state->inner_just_key));
    GUARD(s2n_hash_new(&state->outer));

    return 0;
}

int s2n_hmac_init(struct s2n_hmac_state *state, s2n_hmac_algorithm alg, const void *key, uint32_t klen)
{
    s2n_hash_algorithm hash_alg;
    state->currently_in_hash_block = 0;

    GUARD(s2n_hmac_hash_alg(alg, &hash_alg));
    GUARD(s2n_hmac_digest_size(alg, &state->digest_size));
    GUARD(s2n_hmac_block_size(alg, &state->block_size));
    GUARD(s2n_hmac_hash_block_size(alg, &state->hash_block_size));

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
    /* Keep track of how much of the current hash block is full
     *
     * Why the 4294949760 constant in this code? 4294949760 is the highest 32-bit
     * value that is congruent to 0 modulo all of our HMAC block sizes, that is also
     * at least 16k smaller than 2^32. It therefore has no effect on the mathematical
     * result, and no valid record size can cause it to overflow.
     * 
     * The value was found with the following python code;
     * 
     * x = (2 ** 32) - (2 ** 14)
     * while True:
     *   if x % 40 | x % 48 | x % 64 | x % 128 == 0:
     *     break
     *   x -= 1
     * print x
     *
     * What it does do however is ensure that the mod operation takes a
     * constant number of instruction cycles, regardless of the size of the
     * input. On some platforms, including Intel, the operation can take a
     * smaller number of cycles if the input is "small".
     */
    state->currently_in_hash_block += (4294949760 + size) % state->hash_block_size;
    state->currently_in_hash_block %= state->block_size;

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

int s2n_hmac_digest_two_compression_rounds(struct s2n_hmac_state *state, void *out, uint32_t size)
{
    GUARD(s2n_hmac_digest(state, out, size));

    /* If there were 9 or more bytes of space left in the current hash block
     * then the serialized length, plus an 0x80 byte, will have fit in that block. 
     * If there were fewer than 9 then adding the length will have caused an extra 
     * compression block round. This digest function always does two compression rounds,
     * even if there is no need for the second.
     */
    if (state->currently_in_hash_block > (state->hash_block_size - 9)) {
        return 0;
    }

    return s2n_hash_update(&state->inner, state->xor_pad, state->hash_block_size);
}

int s2n_hmac_free(struct s2n_hmac_state *state)
{
    GUARD(s2n_hash_free(&state->inner));
    GUARD(s2n_hash_free(&state->inner_just_key));
    GUARD(s2n_hash_free(&state->outer));

    return 0;
}

int s2n_hmac_reset(struct s2n_hmac_state *state)
{
    state->currently_in_hash_block = 0;
    GUARD(s2n_hash_copy(&state->inner, &state->inner_just_key));
    return 0;
}

int s2n_hmac_digest_verify(const void *a, const void *b, uint32_t len)
{
    return 0 - !s2n_constant_time_equals(a, b, len);
}

int s2n_hmac_copy(struct s2n_hmac_state *to, struct s2n_hmac_state *from)
{
    /* memcpy cannot be used on s2n_hmac_state as the underying s2n_hash implementation's
     * copy must be used. This is enforced when the s2n_hash implementation is s2n_evp_hash.
     */
    to->alg = from->alg;
    to->hash_block_size = from->hash_block_size;
    to->currently_in_hash_block = from->currently_in_hash_block;
    to->block_size = from->block_size;
    to->digest_size = from->digest_size;

    GUARD(s2n_hash_copy(&to->inner, &from->inner));
    GUARD(s2n_hash_copy(&to->inner_just_key, &from->inner_just_key));
    GUARD(s2n_hash_copy(&to->outer, &from->outer));

    memcpy_check(to->xor_pad, from->xor_pad, sizeof(to->xor_pad));
    memcpy_check(to->digest_pad, from->digest_pad, sizeof(to->digest_pad));

    return 0;
}
