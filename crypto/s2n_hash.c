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
#include "crypto/s2n_hmac.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"

int s2n_hash_hmac_alg(s2n_hash_algorithm hash_alg, s2n_hmac_algorithm *out)
{
    switch(hash_alg) {
    case S2N_HASH_NONE:       *out = S2N_HMAC_NONE;   break;
    case S2N_HASH_MD5:        *out = S2N_HMAC_MD5;    break;
    case S2N_HASH_SHA1:       *out = S2N_HMAC_SHA1;   break;
    case S2N_HASH_SHA224:     *out = S2N_HMAC_SHA224; break;
    case S2N_HASH_SHA256:     *out = S2N_HMAC_SHA256; break;
    case S2N_HASH_SHA384:     *out = S2N_HMAC_SHA384; break;
    case S2N_HASH_SHA512:     *out = S2N_HMAC_SHA512; break;
    case S2N_HASH_MD5_SHA1:   /* Fall through ... */
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

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

/* NOTE: s2n_hash_const_time_get_currently_in_hash_block takes advantage of the fact that
 * hash_block_size is a power of 2. This is true for all hashes we currently support
 * If this ever becomes untrue, this would require fixing*/
int s2n_hash_block_size(s2n_hash_algorithm alg, uint64_t *block_size)
{
    switch(alg) {
    case S2N_HASH_NONE:       *block_size = 64;   break;
    case S2N_HASH_MD5:        *block_size = 64;   break;
    case S2N_HASH_SHA1:       *block_size = 64;   break;
    case S2N_HASH_SHA224:     *block_size = 64;   break;
    case S2N_HASH_SHA256:     *block_size = 64;   break;
    case S2N_HASH_SHA384:     *block_size = 128;  break;
    case S2N_HASH_SHA512:     *block_size = 128;  break;
    case S2N_HASH_MD5_SHA1:   *block_size = 64;   break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
    return 0;
}

/* Return true if hash algorithm is available, false otherwise. */
bool s2n_hash_is_available(s2n_hash_algorithm alg)
{
    switch (alg) {
    case S2N_HASH_MD5:
    case S2N_HASH_MD5_SHA1:
        /* return false if in FIPS mode, as MD5 algs are not available in FIPS mode. */
        return !s2n_is_in_fips_mode();
    case S2N_HASH_NONE:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        return true;
    case S2N_HASH_SENTINEL:
        return false;
    }
    return false;
}

int s2n_hash_is_ready_for_input(struct s2n_hash_state *state)
{
  return state->is_ready_for_input;
}

static int s2n_low_level_hash_new(struct s2n_hash_state *state)
{
    /* s2n_hash_new will always call the corresponding implementation of the s2n_hash
     * being used. For the s2n_low_level_hash implementation, new is a no-op.
     */

    state->is_ready_for_input = 0;
    state->currently_in_hash = 0;
    return 0;
}

static int s2n_low_level_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    switch (alg) {
    case S2N_HASH_NONE:
        break;
    case S2N_HASH_MD5:
        GUARD_OSSL(MD5_Init(&state->digest.low_level.md5), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA1:
        GUARD_OSSL(SHA1_Init(&state->digest.low_level.sha1), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA224:
        GUARD_OSSL(SHA224_Init(&state->digest.low_level.sha224), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA256:
        GUARD_OSSL(SHA256_Init(&state->digest.low_level.sha256), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA384:
        GUARD_OSSL(SHA384_Init(&state->digest.low_level.sha384), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA512:
        GUARD_OSSL(SHA512_Init(&state->digest.low_level.sha512), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_MD5_SHA1:
        GUARD_OSSL(SHA1_Init(&state->digest.low_level.md5_sha1.sha1), S2N_ERR_HASH_INIT_FAILED);;
        GUARD_OSSL(MD5_Init(&state->digest.low_level.md5_sha1.md5), S2N_ERR_HASH_INIT_FAILED);;
        break;

    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    state->alg = alg;
    state->is_ready_for_input = 1;
    state->currently_in_hash = 0;

    return 0;
}

static int s2n_low_level_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
    S2N_ERROR_IF(!state->is_ready_for_input, S2N_ERR_HASH_NOT_READY);

    switch (state->alg) {
    case S2N_HASH_NONE:
        break;
    case S2N_HASH_MD5:
        GUARD_OSSL(MD5_Update(&state->digest.low_level.md5, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    case S2N_HASH_SHA1:
        GUARD_OSSL(SHA1_Update(&state->digest.low_level.sha1, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    case S2N_HASH_SHA224:
        GUARD_OSSL(SHA224_Update(&state->digest.low_level.sha224, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    case S2N_HASH_SHA256:
        GUARD_OSSL(SHA256_Update(&state->digest.low_level.sha256, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    case S2N_HASH_SHA384:
        GUARD_OSSL(SHA384_Update(&state->digest.low_level.sha384, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    case S2N_HASH_SHA512:
        GUARD_OSSL(SHA512_Update(&state->digest.low_level.sha512, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    case S2N_HASH_MD5_SHA1:
        GUARD_OSSL(SHA1_Update(&state->digest.low_level.md5_sha1.sha1, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        GUARD_OSSL(MD5_Update(&state->digest.low_level.md5_sha1.md5, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    state->currently_in_hash += size;

    return 0;
}

static int s2n_low_level_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    S2N_ERROR_IF(!state->is_ready_for_input, S2N_ERR_HASH_NOT_READY);

    switch (state->alg) {
    case S2N_HASH_NONE:
        break;
    case S2N_HASH_MD5:
        eq_check(size, MD5_DIGEST_LENGTH);
	GUARD_OSSL(MD5_Final(out, &state->digest.low_level.md5), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    case S2N_HASH_SHA1:
        eq_check(size, SHA_DIGEST_LENGTH);
        GUARD_OSSL(SHA1_Final(out, &state->digest.low_level.sha1), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    case S2N_HASH_SHA224:
        eq_check(size, SHA224_DIGEST_LENGTH);
        GUARD_OSSL(SHA224_Final(out, &state->digest.low_level.sha224), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    case S2N_HASH_SHA256:
        eq_check(size, SHA256_DIGEST_LENGTH);
        GUARD_OSSL(SHA256_Final(out, &state->digest.low_level.sha256), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    case S2N_HASH_SHA384:
        eq_check(size, SHA384_DIGEST_LENGTH);
        GUARD_OSSL(SHA384_Final(out, &state->digest.low_level.sha384), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    case S2N_HASH_SHA512:
        eq_check(size, SHA512_DIGEST_LENGTH);
        GUARD_OSSL(SHA512_Final(out, &state->digest.low_level.sha512), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    case S2N_HASH_MD5_SHA1:
        eq_check(size, MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH);
        GUARD_OSSL(SHA1_Final(((uint8_t *) out) + MD5_DIGEST_LENGTH, &state->digest.low_level.md5_sha1.sha1), S2N_ERR_HASH_DIGEST_FAILED);
        GUARD_OSSL(MD5_Final(out, &state->digest.low_level.md5_sha1.md5), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    state->currently_in_hash = 0;
    state->is_ready_for_input = 0;
    return 0;
}

static int s2n_low_level_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
    memcpy_check(to, from, sizeof(struct s2n_hash_state));
    return 0;
}

static int s2n_low_level_hash_reset(struct s2n_hash_state *state)
{
    /* hash_init resets the ready_for_input and currently_in_hash fields */
    return s2n_low_level_hash_init(state, state->alg);
}

static int s2n_low_level_hash_free(struct s2n_hash_state *state)
{
    /* s2n_hash_free will always call the corresponding implementation of the s2n_hash
     * being used. For the s2n_low_level_hash implementation, free is a no-op.
     */
    state->is_ready_for_input = 0;
    return 0;
}

static int s2n_evp_hash_new(struct s2n_hash_state *state)
{
    notnull_check(state->digest.high_level.evp.ctx = S2N_EVP_MD_CTX_NEW());
    notnull_check(state->digest.high_level.evp_md5_secondary.ctx = S2N_EVP_MD_CTX_NEW());
    state->is_ready_for_input = 0;
    state->currently_in_hash = 0;

    return 0;
}

static int s2n_evp_hash_allow_md5_for_fips(struct s2n_hash_state *state)
{
    /* This is only to be used for s2n_hash_states that will require MD5 to be used
     * to comply with the TLS 1.0 and 1.1 RFC's for the PRF. MD5 cannot be used
     * outside of the TLS 1.0 and 1.1 PRF when in FIPS mode. When needed, this must
     * be called prior to s2n_hash_init().
     */
    GUARD(s2n_digest_allow_md5_for_fips(&state->digest.high_level.evp_md5_secondary));
    return s2n_digest_allow_md5_for_fips(&state->digest.high_level.evp);
}

static int s2n_evp_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    switch (alg) {
    case S2N_HASH_NONE:
        break;
    case S2N_HASH_MD5:
        GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp.ctx, EVP_md5(), NULL), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA1:
      GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp.ctx, EVP_sha1(), NULL), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA224:
        GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp.ctx, EVP_sha224(), NULL), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA256:
        GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp.ctx, EVP_sha256(), NULL), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA384:
        GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp.ctx, EVP_sha384(), NULL), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_SHA512:
        GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp.ctx, EVP_sha512(), NULL), S2N_ERR_HASH_INIT_FAILED);
        break;
    case S2N_HASH_MD5_SHA1:
        GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp.ctx, EVP_sha1(), NULL), S2N_ERR_HASH_INIT_FAILED);
        GUARD_OSSL(EVP_DigestInit_ex(state->digest.high_level.evp_md5_secondary.ctx, EVP_md5(), NULL), S2N_ERR_HASH_INIT_FAILED);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    state->alg = alg;
    state->is_ready_for_input = 1;
    state->currently_in_hash = 0;

    return 0;
}

static int s2n_evp_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
    S2N_ERROR_IF(!state->is_ready_for_input, S2N_ERR_HASH_NOT_READY);

    switch (state->alg) {
    case S2N_HASH_NONE:
        break;
    case S2N_HASH_MD5:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        GUARD_OSSL(EVP_DigestUpdate(state->digest.high_level.evp.ctx, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    case S2N_HASH_MD5_SHA1:
        GUARD_OSSL(EVP_DigestUpdate(state->digest.high_level.evp.ctx, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        GUARD_OSSL(EVP_DigestUpdate(state->digest.high_level.evp_md5_secondary.ctx, data, size), S2N_ERR_HASH_UPDATE_FAILED);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    state->currently_in_hash += size;

    return 0;
}

static int s2n_evp_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    S2N_ERROR_IF(!state->is_ready_for_input, S2N_ERR_HASH_NOT_READY);

    unsigned int digest_size = size;
    uint8_t expected_digest_size;
    GUARD(s2n_hash_digest_size(state->alg, &expected_digest_size));
    eq_check(digest_size, expected_digest_size);

    /* Used for S2N_HASH_MD5_SHA1 case to specify the exact size of each digest. */
    uint8_t sha1_digest_size;
    unsigned int sha1_primary_digest_size;
    unsigned int md5_secondary_digest_size;

    switch (state->alg) {
    case S2N_HASH_NONE:
        break;
    case S2N_HASH_MD5:
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        GUARD_OSSL(EVP_DigestFinal_ex(state->digest.high_level.evp.ctx, out, &digest_size), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    case S2N_HASH_MD5_SHA1:
        GUARD(s2n_hash_digest_size(S2N_HASH_SHA1, &sha1_digest_size));
        sha1_primary_digest_size = sha1_digest_size;
        md5_secondary_digest_size = digest_size - sha1_primary_digest_size;

        GUARD_OSSL(EVP_DigestFinal_ex(state->digest.high_level.evp.ctx, ((uint8_t *) out) + MD5_DIGEST_LENGTH, &sha1_primary_digest_size), S2N_ERR_HASH_DIGEST_FAILED);
        GUARD_OSSL(EVP_DigestFinal_ex(state->digest.high_level.evp_md5_secondary.ctx, out, &md5_secondary_digest_size), S2N_ERR_HASH_DIGEST_FAILED);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    state->currently_in_hash = 0;
    state->is_ready_for_input = 0;
    return 0;
}

static int s2n_evp_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
    switch (from->alg) {
    case S2N_HASH_NONE:
        break;
    case S2N_HASH_MD5:
        if (s2n_digest_is_md5_allowed_for_fips(&from->digest.high_level.evp)) {
            GUARD(s2n_hash_allow_md5_for_fips(to));
        }
    /* fall through */
    case S2N_HASH_SHA1:
    case S2N_HASH_SHA224:
    case S2N_HASH_SHA256:
    case S2N_HASH_SHA384:
    case S2N_HASH_SHA512:
        GUARD_OSSL(EVP_MD_CTX_copy_ex(to->digest.high_level.evp.ctx, from->digest.high_level.evp.ctx), S2N_ERR_HASH_COPY_FAILED);
        break;
    case S2N_HASH_MD5_SHA1:
        if (s2n_digest_is_md5_allowed_for_fips(&from->digest.high_level.evp)) {
            GUARD(s2n_hash_allow_md5_for_fips(to));
        }
	GUARD_OSSL(EVP_MD_CTX_copy_ex(to->digest.high_level.evp.ctx, from->digest.high_level.evp.ctx), S2N_ERR_HASH_COPY_FAILED);
	GUARD_OSSL(EVP_MD_CTX_copy_ex(to->digest.high_level.evp_md5_secondary.ctx, from->digest.high_level.evp_md5_secondary.ctx), S2N_ERR_HASH_COPY_FAILED);
        break;
    default:
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    to->hash_impl = from->hash_impl;
    to->alg = from->alg;
    to->is_ready_for_input = from->is_ready_for_input;
    to->currently_in_hash = from->currently_in_hash;

    return 0;
}

static int s2n_evp_hash_reset(struct s2n_hash_state *state)
{
    int reset_md5_for_fips = 0;
    if ((state->alg == S2N_HASH_MD5 || state->alg == S2N_HASH_MD5_SHA1) && s2n_digest_is_md5_allowed_for_fips(&state->digest.high_level.evp)) {
        reset_md5_for_fips = 1;
    }

    GUARD_OSSL(S2N_EVP_MD_CTX_RESET(state->digest.high_level.evp.ctx), S2N_ERR_HASH_WIPE_FAILED);
    
    if (state->alg == S2N_HASH_MD5_SHA1) {
        GUARD_OSSL(S2N_EVP_MD_CTX_RESET(state->digest.high_level.evp_md5_secondary.ctx), S2N_ERR_HASH_WIPE_FAILED);
    }

    if (reset_md5_for_fips) {
        GUARD(s2n_hash_allow_md5_for_fips(state));
    }
    /* hash_init resets the ready_for_input and currently_in_hash fields */
    return s2n_evp_hash_init(state, state->alg);
}

static int s2n_evp_hash_free(struct s2n_hash_state *state)
{
    S2N_EVP_MD_CTX_FREE(state->digest.high_level.evp.ctx);
    S2N_EVP_MD_CTX_FREE(state->digest.high_level.evp_md5_secondary.ctx);
    state->digest.high_level.evp.ctx = NULL;
    state->digest.high_level.evp_md5_secondary.ctx = NULL;
    state->is_ready_for_input = 0;
    return 0;
}

static const struct s2n_hash s2n_low_level_hash = {
    .new = &s2n_low_level_hash_new,
    .allow_md5_for_fips = NULL,
    .init = &s2n_low_level_hash_init,
    .update = &s2n_low_level_hash_update,
    .digest = &s2n_low_level_hash_digest,
    .copy = &s2n_low_level_hash_copy,
    .reset = &s2n_low_level_hash_reset,
    .free = &s2n_low_level_hash_free,
};

static const struct s2n_hash s2n_evp_hash = {
    .new = &s2n_evp_hash_new,
    .allow_md5_for_fips = &s2n_evp_hash_allow_md5_for_fips,
    .init = &s2n_evp_hash_init,
    .update = &s2n_evp_hash_update,
    .digest = &s2n_evp_hash_digest,
    .copy = &s2n_evp_hash_copy,
    .reset = &s2n_evp_hash_reset,
    .free = &s2n_evp_hash_free,
};

static int s2n_hash_set_impl(struct s2n_hash_state *state)
{
    state->hash_impl = s2n_is_in_fips_mode() ? &s2n_evp_hash : &s2n_low_level_hash;

    return 0;
}

int s2n_hash_new(struct s2n_hash_state *state)
{
    /* Set hash_impl on initial hash creation.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    GUARD(s2n_hash_set_impl(state));

    notnull_check(state->hash_impl->new);

    return state->hash_impl->new(state);
}

int s2n_hash_allow_md5_for_fips(struct s2n_hash_state *state)
{
    /* Ensure that hash_impl is set, as it may have been reset for s2n_hash_state on s2n_connection_wipe.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    GUARD(s2n_hash_set_impl(state));

    notnull_check(state->hash_impl->allow_md5_for_fips);

    return state->hash_impl->allow_md5_for_fips(state);
}

int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg)
{
    /* Ensure that hash_impl is set, as it may have been reset for s2n_hash_state on s2n_connection_wipe.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    GUARD(s2n_hash_set_impl(state));

    if (s2n_hash_is_available(alg) ||
       ((alg == S2N_HASH_MD5 || alg == S2N_HASH_MD5_SHA1) && s2n_digest_is_md5_allowed_for_fips(&state->digest.high_level.evp))) {
        /* s2n will continue to initialize an "unavailable" hash when s2n is in FIPS mode and
         * FIPS is forcing the hash to be made available.
         */
        notnull_check(state->hash_impl->init);

        return state->hash_impl->init(state, alg);
    } else {
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }
}

int s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size)
{
    notnull_check(state->hash_impl->update);

    return state->hash_impl->update(state, data, size);
}

int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size)
{
    notnull_check(state->hash_impl->digest);

    return state->hash_impl->digest(state, out, size);
}

int s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from)
{
    notnull_check(from->hash_impl->copy);

    return from->hash_impl->copy(to, from);
}

int s2n_hash_reset(struct s2n_hash_state *state)
{
    /* Ensure that hash_impl is set, as it may have been reset for s2n_hash_state on s2n_connection_wipe.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    GUARD(s2n_hash_set_impl(state));

    notnull_check(state->hash_impl->reset);

    return state->hash_impl->reset(state);
}

int s2n_hash_free(struct s2n_hash_state *state)
{
    /* Ensure that hash_impl is set, as it may have been reset for s2n_hash_state on s2n_connection_wipe.
     * When in FIPS mode, the EVP API's must be used for hashes.
     */
    GUARD(s2n_hash_set_impl(state));

    notnull_check(state->hash_impl->free);

    return state->hash_impl->free(state);
}

int s2n_hash_get_currently_in_hash_total(struct s2n_hash_state *state, uint64_t *out)
{
    S2N_ERROR_IF(!state->is_ready_for_input, S2N_ERR_HASH_NOT_READY);

    *out = state->currently_in_hash;
    return 0;
}


/* Calculate, in constant time, the number of bytes currently in the hash_block */
int s2n_hash_const_time_get_currently_in_hash_block(struct s2n_hash_state *state, uint64_t *out)
{
    S2N_ERROR_IF(!state->is_ready_for_input, S2N_ERR_HASH_NOT_READY);
    uint64_t hash_block_size;
    GUARD(s2n_hash_block_size(state->alg, &hash_block_size));

    /* Requires that hash_block_size is a power of 2. This is true for all hashes we currently support
     * If this ever becomes untrue, this would require fixing this*/
    *out = state->currently_in_hash & (hash_block_size - 1);
    return 0;
}
