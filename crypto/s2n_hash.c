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

#include "error/s2n_errno.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"

int s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out)
{
    switch (alg) {
    case S2N_HASH_NONE:     *out = 0;                    break;
    case S2N_HASH_MD5:      *out = MD5_DIGEST_LENGTH;    break;
    case S2N_HASH_SHA1:     *out = SHA_DIGEST_LENGTH;    break;
    case S2N_HASH_SHA224:   *out = SHA224_DIGEST_LENGTH; break;
    case S2N_HASH_SHA256:   *out = SHA256_DIGEST_LENGTH; break;
    case S2N_HASH_SHA384:   *out = SHA384_DIGEST_LENGTH; break;
    case S2N_HASH_SHA512:   *out = SHA512_DIGEST_LENGTH; break;
    case S2N_HASH_MD5_SHA1: *out = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH; break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

static int s2n_low_level_hash_new(struct s2n_hash_state *state)
{
    return 0;
}

static int s2n_low_level_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    int r;
    switch (alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        r = MD5_Init(&state->digest.low_level.md5);
        break;
    case S2N_HASH_SHA1:
        r = SHA1_Init(&state->digest.low_level.sha1);
        break;
    case S2N_HASH_SHA224:
        r = SHA224_Init(&state->digest.low_level.sha224);
        break;
    case S2N_HASH_SHA256:
        r = SHA256_Init(&state->digest.low_level.sha256);
        break;
    case S2N_HASH_SHA384:
        r = SHA384_Init(&state->digest.low_level.sha384);
        break;
    case S2N_HASH_SHA512:
        r = SHA512_Init(&state->digest.low_level.sha512);
        break;
    case S2N_HASH_MD5_SHA1:
        r = SHA1_Init(&state->digest.low_level.md5_sha1.sha1);
        r &= MD5_Init(&state->digest.low_level.md5_sha1.md5);
        break;

    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_INIT_FAILED);
    }

    state->alg = alg;

    return 0;
}

static int s2n_low_level_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
    int r;
    switch (state->alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        r = MD5_Update(&state->digest.low_level.md5, data, size);
        break;
    case S2N_HASH_SHA1:
        r = SHA1_Update(&state->digest.low_level.sha1, data, size);
        break;
    case S2N_HASH_SHA224:
        r = SHA224_Update(&state->digest.low_level.sha224, data, size);
        break;
    case S2N_HASH_SHA256:
        r = SHA256_Update(&state->digest.low_level.sha256, data, size);
        break;
    case S2N_HASH_SHA384:
        r = SHA384_Update(&state->digest.low_level.sha384, data, size);
        break;
    case S2N_HASH_SHA512:
        r = SHA512_Update(&state->digest.low_level.sha512, data, size);
        break;
    case S2N_HASH_MD5_SHA1:
        r = SHA1_Update(&state->digest.low_level.md5_sha1.sha1, data, size);
        r &= MD5_Update(&state->digest.low_level.md5_sha1.md5, data, size);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_UPDATE_FAILED);
    }

    return 0;
}

static int s2n_low_level_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    int r;
    switch (state->alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        eq_check(size, MD5_DIGEST_LENGTH);
        r = MD5_Final(out, &state->digest.low_level.md5);
        break;
    case S2N_HASH_SHA1:
        eq_check(size, SHA_DIGEST_LENGTH);
        r = SHA1_Final(out, &state->digest.low_level.sha1);
        break;
    case S2N_HASH_SHA224:
        eq_check(size, SHA224_DIGEST_LENGTH);
        r = SHA224_Final(out, &state->digest.low_level.sha224);
        break;
    case S2N_HASH_SHA256:
        eq_check(size, SHA256_DIGEST_LENGTH);
        r = SHA256_Final(out, &state->digest.low_level.sha256);
        break;
    case S2N_HASH_SHA384:
        eq_check(size, SHA384_DIGEST_LENGTH);
        r = SHA384_Final(out, &state->digest.low_level.sha384);
        break;
    case S2N_HASH_SHA512:
        eq_check(size, SHA512_DIGEST_LENGTH);
        r = SHA512_Final(out, &state->digest.low_level.sha512);
        break;
    case S2N_HASH_MD5_SHA1:
        eq_check(size, MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH);
        r = SHA1_Final(((uint8_t *) out) + MD5_DIGEST_LENGTH, &state->digest.low_level.md5_sha1.sha1);
        r &= MD5_Final(out, &state->digest.low_level.md5_sha1.md5);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_DIGEST_FAILED);
    }

    return 0;
}

static int s2n_low_level_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
    memcpy_check(to, from, sizeof(struct s2n_hash_state));
    return 0;
}

static int s2n_low_level_hash_reset(struct s2n_hash_state *state)
{
    return s2n_low_level_hash_init(state, state->alg);
}

static int s2n_low_level_hash_free(struct s2n_hash_state *state)
{
    return 0;
}

static int s2n_evp_hash_new(struct s2n_hash_state *state)
{
    notnull_check(state->digest.evp.primary.ctx = S2N_EVP_MD_CTX_NEW());
    notnull_check(state->digest.evp.md5_secondary.ctx = S2N_EVP_MD_CTX_NEW());

    return 0;
}

static int s2n_evp_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    int r;
    switch (alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        r = EVP_DigestInit_ex(state->digest.evp.primary.ctx, EVP_md5(), NULL);
        break;
    case S2N_HASH_SHA1:
        r = EVP_DigestInit_ex(state->digest.evp.primary.ctx, EVP_sha1(), NULL);
        break;
    case S2N_HASH_SHA224:
        r = EVP_DigestInit_ex(state->digest.evp.primary.ctx, EVP_sha224(), NULL);
        break;
    case S2N_HASH_SHA256:
        r = EVP_DigestInit_ex(state->digest.evp.primary.ctx, EVP_sha256(), NULL);
        break;
    case S2N_HASH_SHA384:
        r = EVP_DigestInit_ex(state->digest.evp.primary.ctx, EVP_sha384(), NULL);
        break;
    case S2N_HASH_SHA512:
        r = EVP_DigestInit_ex(state->digest.evp.primary.ctx, EVP_sha512(), NULL);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_DigestInit_ex(state->digest.evp.primary.ctx, EVP_sha1(), NULL);
        r &= EVP_DigestInit_ex(state->digest.evp.md5_secondary.ctx, EVP_md5(), NULL);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_INIT_FAILED);
    }

    state->alg = alg;

    return 0;
}

static int s2n_evp_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
    int r;
    switch (state->alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        r = EVP_DigestUpdate(state->digest.evp.primary.ctx, data, size);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_DigestUpdate(state->digest.evp.primary.ctx, data, size);
        r &= EVP_DigestUpdate(state->digest.evp.md5_secondary.ctx, data, size);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_UPDATE_FAILED);
    }

    return 0;
}

static int s2n_evp_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    int r;
    unsigned int digest_size = size;
    uint8_t expected_digest_size;
    GUARD(s2n_hash_digest_size(state->alg, &expected_digest_size));
    eq_check(digest_size, expected_digest_size);

    switch (state->alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        r = EVP_DigestFinal_ex(state->digest.evp.primary.ctx, out, &digest_size);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_DigestFinal_ex(state->digest.evp.primary.ctx, ((uint8_t *) out) + MD5_DIGEST_LENGTH, &digest_size);
        r &= EVP_DigestFinal_ex(state->digest.evp.md5_secondary.ctx, out, &digest_size);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_DIGEST_FAILED);
    }

    return 0;
}

static int s2n_evp_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
    int r;
    switch (from->alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        r = EVP_MD_CTX_copy_ex(to->digest.evp.primary.ctx, from->digest.evp.primary.ctx);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_MD_CTX_copy_ex(to->digest.evp.primary.ctx, from->digest.evp.primary.ctx);
        r &= EVP_MD_CTX_copy_ex(to->digest.evp.md5_secondary.ctx, from->digest.evp.md5_secondary.ctx);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_COPY_FAILED);
    }

    to->alg = from->alg;
    to->hash_impl = from->hash_impl;

    return 0;
}

static int s2n_evp_hash_reset(struct s2n_hash_state *state)
{
    int r;
    r = S2N_EVP_MD_CTX_RESET(state->digest.evp.primary.ctx);
    
    if (state->alg == S2N_HASH_MD5_SHA1) {
        r &= S2N_EVP_MD_CTX_RESET(state->digest.evp.md5_secondary.ctx);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_WIPE_FAILED);
    }

    return s2n_evp_hash_init(state, state->alg);
}

static int s2n_evp_hash_free(struct s2n_hash_state *state)
{
    S2N_EVP_MD_CTX_FREE(state->digest.evp.primary.ctx);
    S2N_EVP_MD_CTX_FREE(state->digest.evp.md5_secondary.ctx);
    state->digest.evp.primary.ctx = NULL;
    state->digest.evp.md5_secondary.ctx = NULL;

    return 0;
}

const struct s2n_hash s2n_low_level_hash = {
    .new = &s2n_low_level_hash_new,
    .init = &s2n_low_level_hash_init,
    .update = &s2n_low_level_hash_update,
    .digest = &s2n_low_level_hash_digest,
    .copy = &s2n_low_level_hash_copy,
    .reset = &s2n_low_level_hash_reset,
    .free = &s2n_low_level_hash_free,
};

const struct s2n_hash s2n_evp_hash = {
    .new = &s2n_evp_hash_new,
    .init = &s2n_evp_hash_init,
    .update = &s2n_evp_hash_update,
    .digest = &s2n_evp_hash_digest,
    .copy = &s2n_evp_hash_copy,
    .reset = &s2n_evp_hash_reset,
    .free = &s2n_evp_hash_free,
};

int s2n_hash_new(struct s2n_hash_state *state)
{
    if (s2n_is_in_fips_mode()) {
        /* When in FIPS mode, the EVP Digest API's must be used for hashes */
        state->hash_impl = &s2n_evp_hash;
    } else {
        /* Aside from FIPS mode, the low level API's are used for hashes to avoid
         * request-path memory allocation that occurs within EVP_DigestInit and EVP_DigestCopy
         */
        state->hash_impl = &s2n_low_level_hash;
    }

    return state->hash_impl->new(state);
}

int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    if (s2n_is_in_fips_mode()) {
        /* Prevent MD5 hashes from being used when FIPS mode is set. Don't do this within
         * s2n_evp_hash_init as that may be used for non-FIPS at some point in the future.
         */
        switch (alg) {
        case S2N_HASH_MD5:
        case S2N_HASH_MD5_SHA1:
            S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
        default:
            break;
        }
    }

    return state->hash_impl->init(state, alg);
}

int s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
    return state->hash_impl->update(state, data, size);
}

int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    return state->hash_impl->digest(state, out, size);
}

int s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
    return from->hash_impl->copy(to, from);
}

int s2n_hash_reset(struct s2n_hash_state *state)
{
    return state->hash_impl->reset(state);
}

int s2n_hash_free(struct s2n_hash_state *state)
{
    return state->hash_impl->free(state);
}
