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
    /* s2n_hash_new will always call the corresponding implementation of the s2n_hash
     * being used. For the s2n_low_level_hash implementation, new is a no-op.
     */
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
    /* s2n_hash_free will always call the corresponding implementation of the s2n_hash
     * being used. For the s2n_low_level_hash implementation, free is a no-op.
     */
    return 0;
}

static int s2n_evp_hash_new(struct s2n_hash_state *state)
{
    EVP_MD_CTX *primary_ctx = state->digest.high_level.evp.ctx;
    /* A secondary ctx for use with the MD5_SHA1 alg. */
    EVP_MD_CTX *md5_secondary_ctx = state->digest.high_level.evp_md5_secondary.ctx;

    notnull_check(primary_ctx = S2N_EVP_MD_CTX_NEW());
    notnull_check(md5_secondary_ctx = S2N_EVP_MD_CTX_NEW());

    return 0;
}

static int s2n_evp_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    EVP_MD_CTX *primary_ctx = state->digest.high_level.evp.ctx;
    EVP_MD_CTX *md5_secondary_ctx = state->digest.high_level.evp_md5_secondary.ctx;

    int r;
    switch (alg) {
    case S2N_HASH_NONE:
        r = 1;
        break;
    case S2N_HASH_MD5:
        r = EVP_DigestInit_ex(primary_ctx, EVP_md5(), NULL);
        break;
    case S2N_HASH_SHA1:
        r = EVP_DigestInit_ex(primary_ctx, EVP_sha1(), NULL);
        break;
    case S2N_HASH_SHA224:
        r = EVP_DigestInit_ex(primary_ctx, EVP_sha224(), NULL);
        break;
    case S2N_HASH_SHA256:
        r = EVP_DigestInit_ex(primary_ctx, EVP_sha256(), NULL);
        break;
    case S2N_HASH_SHA384:
        r = EVP_DigestInit_ex(primary_ctx, EVP_sha384(), NULL);
        break;
    case S2N_HASH_SHA512:
        r = EVP_DigestInit_ex(primary_ctx, EVP_sha512(), NULL);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_DigestInit_ex(primary_ctx, EVP_sha1(), NULL);
        r &= EVP_DigestInit_ex(md5_secondary_ctx, EVP_md5(), NULL);
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
    EVP_MD_CTX *primary_ctx = state->digest.high_level.evp.ctx;
    EVP_MD_CTX *md5_secondary_ctx = state->digest.high_level.evp_md5_secondary.ctx;

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
        r = EVP_DigestUpdate(primary_ctx, data, size);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_DigestUpdate(primary_ctx, data, size);
        r &= EVP_DigestUpdate(md5_secondary_ctx, data, size);
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
    EVP_MD_CTX *primary_ctx = state->digest.high_level.evp.ctx;
    EVP_MD_CTX *md5_secondary_ctx = state->digest.high_level.evp_md5_secondary.ctx;

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
        r = EVP_DigestFinal_ex(primary_ctx, out, &digest_size);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_DigestFinal_ex(primary_ctx, ((uint8_t *) out) + MD5_DIGEST_LENGTH, &digest_size);
        r &= EVP_DigestFinal_ex(md5_secondary_ctx, out, &digest_size);
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
    EVP_MD_CTX *from_primary_ctx = from->digest.high_level.evp.ctx;
    EVP_MD_CTX *to_primary_ctx = to->digest.high_level.evp.ctx;
    EVP_MD_CTX *from_md5_secondary_ctx = from->digest.high_level.evp_md5_secondary.ctx;
    EVP_MD_CTX *to_md5_secondary_ctx = to->digest.high_level.evp_md5_secondary.ctx;

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
        r = EVP_MD_CTX_copy_ex(to_primary_ctx, from_primary_ctx);
        break;
    case S2N_HASH_MD5_SHA1:
        r = EVP_MD_CTX_copy_ex(to_primary_ctx, from_primary_ctx);
        r &= EVP_MD_CTX_copy_ex(to_md5_secondary_ctx, from_md5_secondary_ctx);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_COPY_FAILED);
    }
    to->hash_impl = from->hash_impl;
    to->alg = from->alg;

    return 0;
}

static int s2n_evp_hash_reset(struct s2n_hash_state *state)
{
    EVP_MD_CTX *primary_ctx = state->digest.high_level.evp.ctx;
    EVP_MD_CTX *md5_secondary_ctx = state->digest.high_level.evp_md5_secondary.ctx;

    int r;
    r = S2N_EVP_MD_CTX_RESET(primary_ctx);
    
    if (state->alg == S2N_HASH_MD5_SHA1) {
        r &= S2N_EVP_MD_CTX_RESET(md5_secondary_ctx);
    }

    if (r == 0) {
        S2N_ERROR(S2N_ERR_HASH_WIPE_FAILED);
    }

    return s2n_evp_hash_init(state, state->alg);
}

static int s2n_evp_hash_free(struct s2n_hash_state *state)
{
    EVP_MD_CTX *primary_ctx = state->digest.high_level.evp.ctx;
    EVP_MD_CTX *md5_secondary_ctx = state->digest.high_level.evp_md5_secondary.ctx;

    S2N_EVP_MD_CTX_FREE(primary_ctx);
    S2N_EVP_MD_CTX_FREE(md5_secondary_ctx);
    primary_ctx = NULL;
    md5_secondary_ctx = NULL;

    return 0;
}

static const struct s2n_hash s2n_low_level_hash = {
    .new = &s2n_low_level_hash_new,
    .init = &s2n_low_level_hash_init,
    .update = &s2n_low_level_hash_update,
    .digest = &s2n_low_level_hash_digest,
    .copy = &s2n_low_level_hash_copy,
    .reset = &s2n_low_level_hash_reset,
    .free = &s2n_low_level_hash_free,
};

static const struct s2n_hash s2n_evp_hash = {
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
    /* Set hash_impl on initial hash creation.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    s2n_is_in_fips_mode() ? (state->hash_impl = &s2n_evp_hash) : (state->hash_impl = &s2n_low_level_hash);

    return state->hash_impl->new(state);
}

int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    /* Ensure that hash_impl is set, as it may have been reset for s2n_hash_state on s2n_connection_wipe.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    s2n_is_in_fips_mode() ? (state->hash_impl = &s2n_evp_hash) : (state->hash_impl = &s2n_low_level_hash);

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
    /* Ensure that hash_impl is set, as it may have been reset for s2n_hash_state on s2n_connection_wipe.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    s2n_is_in_fips_mode() ? (state->hash_impl = &s2n_evp_hash) : (state->hash_impl = &s2n_low_level_hash);

    return state->hash_impl->free(state);
}
