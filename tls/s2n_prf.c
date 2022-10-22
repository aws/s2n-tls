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

#include <sys/param.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

static int s2n_sslv3_prf(struct s2n_connection *conn, struct s2n_blob *secret, struct s2n_blob *seed_a,
        struct s2n_blob *seed_b, struct s2n_blob *seed_c, struct s2n_blob *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->handshake.hashes);
    struct s2n_hash_state *workspace = &conn->handshake.hashes->hash_workspace;

    /* FIPS specifically allows MD5 for the legacy PRF */
    if (s2n_is_in_fips_mode() && conn->actual_protocol_version < S2N_TLS12) {
        POSIX_GUARD(s2n_hash_allow_md5_for_fips(workspace));
    }

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;
    uint8_t iteration = 1;

    uint8_t md5_digest[MD5_DIGEST_LENGTH] = { 0 }, sha_digest[SHA_DIGEST_LENGTH] = { 0 };

    uint8_t A = 'A';
    while (outputlen) {
        struct s2n_hash_state *sha1 = workspace;
        POSIX_GUARD(s2n_hash_reset(sha1));
        POSIX_GUARD(s2n_hash_init(sha1, S2N_HASH_SHA1));

        for (int i = 0; i < iteration; i++) {
            POSIX_GUARD(s2n_hash_update(sha1, &A, 1));
        }

        POSIX_GUARD(s2n_hash_update(sha1, secret->data, secret->size));
        POSIX_GUARD(s2n_hash_update(sha1, seed_a->data, seed_a->size));

        if (seed_b) {
            POSIX_GUARD(s2n_hash_update(sha1, seed_b->data, seed_b->size));
            if (seed_c) {
                POSIX_GUARD(s2n_hash_update(sha1, seed_c->data, seed_c->size));
            }
        }

        POSIX_GUARD(s2n_hash_digest(sha1, sha_digest, sizeof(sha_digest)));

        struct s2n_hash_state *md5 = workspace;
        POSIX_GUARD(s2n_hash_reset(md5));
        POSIX_GUARD(s2n_hash_init(md5, S2N_HASH_MD5));
        POSIX_GUARD(s2n_hash_update(md5, secret->data, secret->size));
        POSIX_GUARD(s2n_hash_update(md5, sha_digest, sizeof(sha_digest)));
        POSIX_GUARD(s2n_hash_digest(md5, md5_digest, sizeof(md5_digest)));

        uint32_t bytes_to_copy = MIN(outputlen, sizeof(md5_digest));

        POSIX_CHECKED_MEMCPY(output, md5_digest, bytes_to_copy);

        outputlen -= bytes_to_copy;
        output += bytes_to_copy;

        /* Increment the letter */
        A++;
        iteration++;
    }

    return 0;
}

static int s2n_init_md_from_hmac_alg(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg){
    switch (alg) {
        case S2N_HMAC_SSLv3_MD5:
        case S2N_HMAC_MD5:
            ws->p_hash.evp_hmac.evp_digest.md = EVP_md5();
            break;
        case S2N_HMAC_SSLv3_SHA1:
        case S2N_HMAC_SHA1:
            ws->p_hash.evp_hmac.evp_digest.md = EVP_sha1();
            break;
        case S2N_HMAC_SHA224:
            ws->p_hash.evp_hmac.evp_digest.md = EVP_sha224();
            break;
        case S2N_HMAC_SHA256:
            ws->p_hash.evp_hmac.evp_digest.md = EVP_sha256();
            break;
        case S2N_HMAC_SHA384:
            ws->p_hash.evp_hmac.evp_digest.md = EVP_sha384();
            break;
        case S2N_HMAC_SHA512:
            ws->p_hash.evp_hmac.evp_digest.md = EVP_sha512();
            break;
        default:
            POSIX_BAIL(S2N_ERR_P_HASH_INVALID_ALGORITHM);
    }
    return S2N_SUCCESS;
}

#if !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC)
static int s2n_evp_pkey_p_hash_alloc(struct s2n_prf_working_space *ws)
{
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.evp_digest.ctx = S2N_EVP_MD_CTX_NEW());
    return 0;
}

static int s2n_evp_pkey_p_hash_digest_init(struct s2n_prf_working_space *ws)
{
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.evp_digest.md);
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.evp_digest.ctx);
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.ctx.evp_pkey);
 
    /* Ignore the MD5 check when in FIPS mode to comply with the TLS 1.0 RFC */
    if (s2n_is_in_fips_mode()) {
        POSIX_GUARD(s2n_digest_allow_md5_for_fips(&ws->p_hash.evp_hmac.evp_digest));
    }

    POSIX_GUARD_OSSL(EVP_DigestSignInit(ws->p_hash.evp_hmac.evp_digest.ctx, NULL, ws->p_hash.evp_hmac.evp_digest.md, NULL, ws->p_hash.evp_hmac.ctx.evp_pkey),
           S2N_ERR_P_HASH_INIT_FAILED);

    return 0;
}

static int s2n_evp_pkey_p_hash_init(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret)
{
    /* Initialize the message digest */
    POSIX_GUARD(s2n_init_md_from_hmac_alg(ws, alg));

    /* Initialize the mac key using the provided secret */
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.ctx.evp_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret->data, secret->size));

    /* Initialize the message digest context with the above message digest and mac key */
    return s2n_evp_pkey_p_hash_digest_init(ws);
}

static int s2n_evp_pkey_p_hash_update(struct s2n_prf_working_space *ws, const void *data, uint32_t size)
{
    POSIX_GUARD_OSSL(EVP_DigestSignUpdate(ws->p_hash.evp_hmac.evp_digest.ctx, data, (size_t)size), S2N_ERR_P_HASH_UPDATE_FAILED);

    return 0;
}

static int s2n_evp_pkey_p_hash_final(struct s2n_prf_working_space *ws, void *digest, uint32_t size)
{
    /* EVP_DigestSign API's require size_t data structures */
    size_t digest_size = size;

    POSIX_GUARD_OSSL(EVP_DigestSignFinal(ws->p_hash.evp_hmac.evp_digest.ctx, (unsigned char *)digest, &digest_size), S2N_ERR_P_HASH_FINAL_FAILED);

    return 0;
}

static int s2n_evp_pkey_p_hash_wipe(struct s2n_prf_working_space *ws)
{
    POSIX_GUARD_OSSL(S2N_EVP_MD_CTX_RESET(ws->p_hash.evp_hmac.evp_digest.ctx), S2N_ERR_P_HASH_WIPE_FAILED);

    return 0;
}

static int s2n_evp_pkey_p_hash_reset(struct s2n_prf_working_space *ws)
{
    POSIX_GUARD(s2n_evp_pkey_p_hash_wipe(ws));

    /*
     * On some cleanup paths s2n_evp_pkey_p_hash_reset can be called before s2n_evp_pkey_p_hash_init so there is nothing
     * to reset.
     */
    if (ws->p_hash.evp_hmac.ctx.evp_pkey == NULL) {
        return S2N_SUCCESS;
    }
    return s2n_evp_pkey_p_hash_digest_init(ws);
}

static int s2n_evp_pkey_p_hash_cleanup(struct s2n_prf_working_space *ws)
{
    /* Prepare the workspace md_ctx for the next p_hash */
    POSIX_GUARD(s2n_evp_pkey_p_hash_wipe(ws));

    /* Free mac key - PKEYs cannot be reused */
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.ctx.evp_pkey);
    EVP_PKEY_free(ws->p_hash.evp_hmac.ctx.evp_pkey);
    ws->p_hash.evp_hmac.ctx.evp_pkey = NULL;

    return 0;
}

static int s2n_evp_pkey_p_hash_free(struct s2n_prf_working_space *ws)
{
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.evp_digest.ctx);
    S2N_EVP_MD_CTX_FREE(ws->p_hash.evp_hmac.evp_digest.ctx);
    ws->p_hash.evp_hmac.evp_digest.ctx = NULL;

    return 0;
}

static const struct s2n_p_hash_hmac s2n_evp_pkey_p_hash_hmac = {
    .alloc = &s2n_evp_pkey_p_hash_alloc,
    .init = &s2n_evp_pkey_p_hash_init,
    .update = &s2n_evp_pkey_p_hash_update,
    .final = &s2n_evp_pkey_p_hash_final,
    .reset = &s2n_evp_pkey_p_hash_reset,
    .cleanup = &s2n_evp_pkey_p_hash_cleanup,
    .free = &s2n_evp_pkey_p_hash_free,
};
#else
static int s2n_evp_hmac_p_hash_alloc(struct s2n_prf_working_space *ws)
{
    POSIX_ENSURE_REF(ws->p_hash.evp_hmac.ctx.hmac_ctx = HMAC_CTX_new());
    return S2N_SUCCESS;
}

static int s2n_evp_hmac_p_hash_init(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret)
{
    /* Figure out the correct EVP_MD from s2n_hmac_algorithm  */
    POSIX_GUARD(s2n_init_md_from_hmac_alg(ws, alg));

    /* Initialize the mac and digest */
    POSIX_GUARD_OSSL(HMAC_Init_ex(ws->p_hash.evp_hmac.ctx.hmac_ctx, secret->data, secret->size, ws->p_hash.evp_hmac.evp_digest.md, NULL), S2N_ERR_P_HASH_INIT_FAILED);
    return S2N_SUCCESS;
}

static int s2n_evp_hmac_p_hash_update(struct s2n_prf_working_space *ws, const void *data, uint32_t size)
{
    POSIX_GUARD_OSSL(HMAC_Update(ws->p_hash.evp_hmac.ctx.hmac_ctx, data, (size_t)size), S2N_ERR_P_HASH_UPDATE_FAILED);
    return S2N_SUCCESS;
}

static int s2n_evp_hmac_p_hash_final(struct s2n_prf_working_space *ws, void *digest, uint32_t size)
{
    /* HMAC_Final API's require size_t data structures */
    unsigned int digest_size = size;
    POSIX_GUARD_OSSL(HMAC_Final(ws->p_hash.evp_hmac.ctx.hmac_ctx, (unsigned char *)digest, &digest_size), S2N_ERR_P_HASH_FINAL_FAILED);
    return S2N_SUCCESS;
}

static int s2n_evp_hmac_p_hash_reset(struct s2n_prf_working_space *ws)
{
    POSIX_ENSURE_REF(ws);
    if (ws->p_hash.evp_hmac.evp_digest.md == NULL) {
        return S2N_SUCCESS;
    }
    POSIX_GUARD_OSSL(HMAC_Init_ex(ws->p_hash.evp_hmac.ctx.hmac_ctx, NULL, 0, ws->p_hash.evp_hmac.evp_digest.md, NULL), S2N_ERR_P_HASH_INIT_FAILED);
    return S2N_SUCCESS;
}

static int s2n_evp_hmac_p_hash_cleanup(struct s2n_prf_working_space *ws)
{
    /* Prepare the workspace md_ctx for the next p_hash */
    HMAC_CTX_reset(ws->p_hash.evp_hmac.ctx.hmac_ctx);
    return S2N_SUCCESS;
}

static int s2n_evp_hmac_p_hash_free(struct s2n_prf_working_space *ws)
{
    HMAC_CTX_free(ws->p_hash.evp_hmac.ctx.hmac_ctx);
    return S2N_SUCCESS;
}

static const struct s2n_p_hash_hmac s2n_evp_hmac_p_hash_hmac = {
    .alloc = &s2n_evp_hmac_p_hash_alloc,
    .init = &s2n_evp_hmac_p_hash_init,
    .update = &s2n_evp_hmac_p_hash_update,
    .final = &s2n_evp_hmac_p_hash_final,
    .reset = &s2n_evp_hmac_p_hash_reset,
    .cleanup = &s2n_evp_hmac_p_hash_cleanup,
    .free = &s2n_evp_hmac_p_hash_free,
};
#endif /* !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC) */

static int s2n_hmac_p_hash_new(struct s2n_prf_working_space *ws)
{
    POSIX_GUARD(s2n_hmac_new(&ws->p_hash.s2n_hmac));

    return s2n_hmac_init(&ws->p_hash.s2n_hmac, S2N_HMAC_NONE, NULL, 0);
}

static int s2n_hmac_p_hash_init(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret)
{
    return s2n_hmac_init(&ws->p_hash.s2n_hmac, alg, secret->data, secret->size);
}

static int s2n_hmac_p_hash_update(struct s2n_prf_working_space *ws, const void *data, uint32_t size)
{
    return s2n_hmac_update(&ws->p_hash.s2n_hmac, data, size);
}

static int s2n_hmac_p_hash_digest(struct s2n_prf_working_space *ws, void *digest, uint32_t size)
{
    return s2n_hmac_digest(&ws->p_hash.s2n_hmac, digest, size);
}

static int s2n_hmac_p_hash_reset(struct s2n_prf_working_space *ws)
{
    /* If we actually initialized s2n_hmac, wipe it.
     * A valid, initialized s2n_hmac_state will have a valid block size.
     */
    if (ws->p_hash.s2n_hmac.hash_block_size != 0) {
        return s2n_hmac_reset(&ws->p_hash.s2n_hmac);
    }
    return S2N_SUCCESS;
}

static int s2n_hmac_p_hash_cleanup(struct s2n_prf_working_space *ws)
{
    return s2n_hmac_p_hash_reset(ws);
}

static int s2n_hmac_p_hash_free(struct s2n_prf_working_space *ws)
{
    return s2n_hmac_free(&ws->p_hash.s2n_hmac);
}

static const struct s2n_p_hash_hmac s2n_internal_p_hash_hmac = {
    .alloc = &s2n_hmac_p_hash_new,
    .init = &s2n_hmac_p_hash_init,
    .update = &s2n_hmac_p_hash_update,
    .final = &s2n_hmac_p_hash_digest,
    .reset = &s2n_hmac_p_hash_reset,
    .cleanup = &s2n_hmac_p_hash_cleanup,
    .free = &s2n_hmac_p_hash_free,
};

const struct s2n_p_hash_hmac *s2n_get_hmac_implementation() {
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
    return s2n_is_in_fips_mode() ? &s2n_evp_hmac_p_hash_hmac : &s2n_internal_p_hash_hmac;
#else
    return s2n_is_in_fips_mode() ? &s2n_evp_pkey_p_hash_hmac : &s2n_internal_p_hash_hmac;
#endif
}

static int s2n_p_hash(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret, struct s2n_blob *label,
                      struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *seed_c, struct s2n_blob *out)
{
    uint8_t digest_size;
    POSIX_GUARD(s2n_hmac_digest_size(alg, &digest_size));

    const struct s2n_p_hash_hmac *hmac = s2n_get_hmac_implementation();

    /* First compute hmac(secret + A(0)) */
    POSIX_GUARD(hmac->init(ws, alg, secret));
    POSIX_GUARD(hmac->update(ws, label->data, label->size));
    POSIX_GUARD(hmac->update(ws, seed_a->data, seed_a->size));

    if (seed_b) {
        POSIX_GUARD(hmac->update(ws, seed_b->data, seed_b->size));
        if (seed_c) {
            POSIX_GUARD(hmac->update(ws, seed_c->data, seed_c->size));
        }
    }
    POSIX_GUARD(hmac->final(ws, ws->digest0, digest_size));

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;

    while (outputlen) {
        /* Now compute hmac(secret + A(N - 1) + seed) */
        POSIX_GUARD(hmac->reset(ws));
        POSIX_GUARD(hmac->update(ws, ws->digest0, digest_size));

        /* Add the label + seed and compute this round's A */
        POSIX_GUARD(hmac->update(ws, label->data, label->size));
        POSIX_GUARD(hmac->update(ws, seed_a->data, seed_a->size));
        if (seed_b) {
            POSIX_GUARD(hmac->update(ws, seed_b->data, seed_b->size));
            if (seed_c) {
                POSIX_GUARD(hmac->update(ws, seed_c->data, seed_c->size));
            }
        }

        POSIX_GUARD(hmac->final(ws, ws->digest1, digest_size));

        uint32_t bytes_to_xor = MIN(outputlen, digest_size);

        for (uint32_t i = 0; i < bytes_to_xor; i++) {
            *output ^= ws->digest1[i];
            output++;
            outputlen--;
        }

        /* Stash a digest of A(N), in A(N), for the next round */
        POSIX_GUARD(hmac->reset(ws));
        POSIX_GUARD(hmac->update(ws, ws->digest0, digest_size));
        POSIX_GUARD(hmac->final(ws, ws->digest0, digest_size));
    }

    POSIX_GUARD(hmac->cleanup(ws));

    return 0;
}

S2N_RESULT s2n_prf_new(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_EQ(conn->prf_space, NULL);

    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_realloc(&mem, sizeof(struct s2n_prf_working_space)));
    RESULT_GUARD_POSIX(s2n_blob_zero(&mem));
    conn->prf_space = (struct s2n_prf_working_space*)(void*) mem.data;
    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);

    /* Allocate the hmac state */
    const struct s2n_p_hash_hmac *hmac_impl = s2n_get_hmac_implementation();
    RESULT_GUARD_POSIX(hmac_impl->alloc(conn->prf_space));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_prf_wipe(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->prf_space);

    const struct s2n_p_hash_hmac *hmac_impl = s2n_get_hmac_implementation();
    RESULT_GUARD_POSIX(hmac_impl->reset(conn->prf_space));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_prf_free(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    if (conn->prf_space == NULL) {
        return S2N_RESULT_OK;
    }

    const struct s2n_p_hash_hmac *hmac_impl = s2n_get_hmac_implementation();
    RESULT_GUARD_POSIX(hmac_impl->free(conn->prf_space));

    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) &conn->prf_space, sizeof(struct s2n_prf_working_space)));
    return S2N_RESULT_OK;
}

static int s2n_prf(struct s2n_connection *conn, struct s2n_blob *secret, struct s2n_blob *label, struct s2n_blob *seed_a,
                   struct s2n_blob *seed_b, struct s2n_blob *seed_c, struct s2n_blob *out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(secret);
    POSIX_ENSURE_REF(conn->prf_space);
    POSIX_ENSURE_REF(conn->secure);

    /* seed_a is always required, seed_b is optional, if seed_c is provided seed_b must also be provided */
    S2N_ERROR_IF(seed_a == NULL, S2N_ERR_PRF_INVALID_SEED);
    S2N_ERROR_IF(seed_b == NULL && seed_c != NULL, S2N_ERR_PRF_INVALID_SEED);

    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_prf(conn, secret, seed_a, seed_b, seed_c, out);
    }

    /* We zero the out blob because p_hash works by XOR'ing with the existing
     * buffer. This is a little convoluted but means we can avoid dynamic memory
     * allocation. When we call p_hash once (in the TLS1.2 case) it will produce
     * the right values. When we call it twice in the regular case, the two
     * outputs will be XORd just ass the TLS 1.0 and 1.1 RFCs require.
     */
    POSIX_GUARD(s2n_blob_zero(out));
    
    if (conn->actual_protocol_version == S2N_TLS12) {
        return s2n_p_hash(conn->prf_space, conn->secure->cipher_suite->prf_alg, secret, label, seed_a, seed_b,
                          seed_c, out);
    }

    struct s2n_blob half_secret = {.data = secret->data,.size = (secret->size + 1) / 2 };

    POSIX_GUARD(s2n_p_hash(conn->prf_space, S2N_HMAC_MD5, &half_secret, label, seed_a, seed_b, seed_c, out));
    half_secret.data += secret->size - half_secret.size;
    POSIX_GUARD(s2n_p_hash(conn->prf_space, S2N_HMAC_SHA1, &half_secret, label, seed_a, seed_b, seed_c, out));

    return 0;
}

int s2n_tls_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob client_random = {.size = sizeof(conn->handshake_params.client_random), .data = conn->handshake_params.client_random};
    struct s2n_blob server_random = {.size = sizeof(conn->handshake_params.server_random), .data = conn->handshake_params.server_random};
    struct s2n_blob master_secret = {.size = sizeof(conn->secrets.tls12.master_secret), .data = conn->secrets.tls12.master_secret};

    uint8_t master_secret_label[] = "master secret";
    struct s2n_blob label = {.size = sizeof(master_secret_label) - 1, .data = master_secret_label};

    return s2n_prf(conn, premaster_secret, &label, &client_random, &server_random, NULL, &master_secret);
}

int s2n_hybrid_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob client_random = {.size = sizeof(conn->handshake_params.client_random), .data = conn->handshake_params.client_random};
    struct s2n_blob server_random = {.size = sizeof(conn->handshake_params.server_random), .data = conn->handshake_params.server_random};
    struct s2n_blob master_secret = {.size = sizeof(conn->secrets.tls12.master_secret), .data = conn->secrets.tls12.master_secret};

    uint8_t master_secret_label[] = "hybrid master secret";
    struct s2n_blob label = {.size = sizeof(master_secret_label) - 1, .data = master_secret_label};

    return s2n_prf(conn, premaster_secret, &label, &client_random, &server_random, &conn->kex_params.client_key_exchange_message, &master_secret);
}

int s2n_prf_calculate_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);

    POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(conn), CLIENT_KEY);

    if(!conn->ems_negotiated) {
        POSIX_GUARD(s2n_tls_prf_master_secret(conn, premaster_secret));
        return S2N_SUCCESS;
    }

    /* Only the client writes the Client Key Exchange message */
    if (conn->mode == S2N_CLIENT) {
        POSIX_GUARD(s2n_handshake_finish_header(&conn->handshake.io));
    }
    struct s2n_stuffer client_key_message = conn->handshake.io;
    POSIX_GUARD(s2n_stuffer_reread(&client_key_message));
    uint32_t client_key_message_size = s2n_stuffer_data_available(&client_key_message);
    struct s2n_blob client_key_blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&client_key_blob, client_key_message.blob.data, client_key_message_size));

    uint8_t data[S2N_MAX_DIGEST_LEN] = { 0 };
    struct s2n_blob digest = { 0 };
    POSIX_GUARD(s2n_blob_init(&digest, data, sizeof(data)));
    if (conn->actual_protocol_version < S2N_TLS12) {
        uint8_t sha1_data[S2N_MAX_DIGEST_LEN] = { 0 };
        struct s2n_blob sha1_digest = { 0 };
        POSIX_GUARD(s2n_blob_init(&sha1_digest, sha1_data, sizeof(sha1_data)));
        POSIX_GUARD_RESULT(s2n_prf_get_digest_for_ems(conn, &client_key_blob, S2N_HASH_MD5, &digest));
        POSIX_GUARD_RESULT(s2n_prf_get_digest_for_ems(conn, &client_key_blob, S2N_HASH_SHA1, &sha1_digest));
        POSIX_GUARD_RESULT(s2n_tls_prf_extended_master_secret(conn, premaster_secret, &digest, &sha1_digest));
    } else {
        s2n_hmac_algorithm prf_alg = conn->secure->cipher_suite->prf_alg;
        s2n_hash_algorithm hash_alg = 0;
        POSIX_GUARD(s2n_hmac_hash_alg(prf_alg, &hash_alg));
        POSIX_GUARD_RESULT(s2n_prf_get_digest_for_ems(conn, &client_key_blob, hash_alg, &digest));
        POSIX_GUARD_RESULT(s2n_tls_prf_extended_master_secret(conn, premaster_secret, &digest, NULL));
    }
    return S2N_SUCCESS;
}

/**
 *= https://tools.ietf.org/rfc/rfc7627#section-4
 *# When the extended master secret extension is negotiated in a full
 *# handshake, the "master_secret" is computed as
 *#
 *# master_secret = PRF(pre_master_secret, "extended master secret",
 *#                    session_hash)
 *#                    [0..47];
 */
S2N_RESULT s2n_tls_prf_extended_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret, struct s2n_blob *session_hash, struct s2n_blob *sha1_hash)
{
    struct s2n_blob extended_master_secret = {.size = sizeof(conn->secrets.tls12.master_secret), .data = conn->secrets.tls12.master_secret};

    uint8_t extended_master_secret_label[] = "extended master secret";
    /* Subtract one from the label size to remove the "\0" */
    struct s2n_blob label = {.size = sizeof(extended_master_secret_label) - 1, .data = extended_master_secret_label};

    RESULT_GUARD_POSIX(s2n_prf(conn, premaster_secret, &label, session_hash, sha1_hash, NULL, &extended_master_secret));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_prf_get_digest_for_ems(struct s2n_connection *conn, struct s2n_blob *message, s2n_hash_algorithm hash_alg, struct s2n_blob *output)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->handshake.hashes);
    RESULT_ENSURE_REF(output);

    struct s2n_hash_state *hash_state = &conn->handshake.hashes->hash_workspace;
    RESULT_GUARD(s2n_handshake_copy_hash_state(conn, hash_alg, hash_state));
    RESULT_GUARD_POSIX(s2n_hash_update(hash_state, message->data, message->size));

    uint8_t digest_size = 0;
    RESULT_GUARD_POSIX(s2n_hash_digest_size(hash_alg, &digest_size));
    RESULT_ENSURE_GTE(output->size, digest_size);
    RESULT_GUARD_POSIX(s2n_hash_digest(hash_state, output->data, digest_size));
    output->size = digest_size;

    return S2N_RESULT_OK;
}

static int s2n_sslv3_finished(struct s2n_connection *conn, uint8_t prefix[4], struct s2n_hash_state *hash_workspace, uint8_t * out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->handshake.hashes);

    uint8_t xorpad1[48] =
        { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
    };
    uint8_t xorpad2[48] =
        { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
    };
    uint8_t *md5_digest = out;
    uint8_t *sha_digest = out + MD5_DIGEST_LENGTH;

    POSIX_GUARD_RESULT(s2n_handshake_set_finished_len(conn, MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH));

    struct s2n_hash_state *md5 = hash_workspace;
    POSIX_GUARD(s2n_hash_copy(md5, &conn->handshake.hashes->md5));
    POSIX_GUARD(s2n_hash_update(md5, prefix, 4));
    POSIX_GUARD(s2n_hash_update(md5, conn->secrets.tls12.master_secret, sizeof(conn->secrets.tls12.master_secret)));
    POSIX_GUARD(s2n_hash_update(md5, xorpad1, 48));
    POSIX_GUARD(s2n_hash_digest(md5, md5_digest, MD5_DIGEST_LENGTH));
    POSIX_GUARD(s2n_hash_reset(md5));
    POSIX_GUARD(s2n_hash_update(md5, conn->secrets.tls12.master_secret, sizeof(conn->secrets.tls12.master_secret)));
    POSIX_GUARD(s2n_hash_update(md5, xorpad2, 48));
    POSIX_GUARD(s2n_hash_update(md5, md5_digest, MD5_DIGEST_LENGTH));
    POSIX_GUARD(s2n_hash_digest(md5, md5_digest, MD5_DIGEST_LENGTH));
    POSIX_GUARD(s2n_hash_reset(md5));

    struct s2n_hash_state *sha1 = hash_workspace;
    POSIX_GUARD(s2n_hash_copy(sha1, &conn->handshake.hashes->sha1));
    POSIX_GUARD(s2n_hash_update(sha1, prefix, 4));
    POSIX_GUARD(s2n_hash_update(sha1, conn->secrets.tls12.master_secret, sizeof(conn->secrets.tls12.master_secret)));
    POSIX_GUARD(s2n_hash_update(sha1, xorpad1, 40));
    POSIX_GUARD(s2n_hash_digest(sha1, sha_digest, SHA_DIGEST_LENGTH));
    POSIX_GUARD(s2n_hash_reset(sha1));
    POSIX_GUARD(s2n_hash_update(sha1, conn->secrets.tls12.master_secret, sizeof(conn->secrets.tls12.master_secret)));
    POSIX_GUARD(s2n_hash_update(sha1, xorpad2, 40));
    POSIX_GUARD(s2n_hash_update(sha1, sha_digest, SHA_DIGEST_LENGTH));
    POSIX_GUARD(s2n_hash_digest(sha1, sha_digest, SHA_DIGEST_LENGTH));
    POSIX_GUARD(s2n_hash_reset(sha1));

    return 0;
}

static int s2n_sslv3_client_finished(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->handshake.hashes);

    uint8_t prefix[4] = { 0x43, 0x4c, 0x4e, 0x54 };

    return s2n_sslv3_finished(conn, prefix, &conn->handshake.hashes->hash_workspace, conn->handshake.client_finished);
}

static int s2n_sslv3_server_finished(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->handshake.hashes);

    uint8_t prefix[4] = { 0x53, 0x52, 0x56, 0x52 };

    return s2n_sslv3_finished(conn, prefix, &conn->handshake.hashes->hash_workspace, conn->handshake.server_finished);
}

int s2n_prf_client_finished(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);
    POSIX_ENSURE_REF(conn->handshake.hashes);

    struct s2n_blob master_secret, md5, sha;
    uint8_t md5_digest[MD5_DIGEST_LENGTH];
    uint8_t sha_digest[SHA384_DIGEST_LENGTH];
    uint8_t client_finished_label[] = "client finished";
    struct s2n_blob client_finished = {0};
    struct s2n_blob label = {0};

    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_client_finished(conn);
    }

    client_finished.data = conn->handshake.client_finished;
    client_finished.size = S2N_TLS_FINISHED_LEN;
    POSIX_GUARD_RESULT(s2n_handshake_set_finished_len(conn, client_finished.size));
    label.data = client_finished_label;
    label.size = sizeof(client_finished_label) - 1;

    master_secret.data = conn->secrets.tls12.master_secret;
    master_secret.size = sizeof(conn->secrets.tls12.master_secret);
    if (conn->actual_protocol_version == S2N_TLS12) {
        switch (conn->secure->cipher_suite->prf_alg) {
        case S2N_HMAC_SHA256:
            POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->sha256));
            POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, sha_digest, SHA256_DIGEST_LENGTH));
            sha.size = SHA256_DIGEST_LENGTH;
            break;
        case S2N_HMAC_SHA384:
            POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->sha384));
            POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, sha_digest, SHA384_DIGEST_LENGTH));
            sha.size = SHA384_DIGEST_LENGTH;
            break;
        default:
            POSIX_BAIL(S2N_ERR_PRF_INVALID_ALGORITHM);
        }

        sha.data = sha_digest;
        return s2n_prf(conn, &master_secret, &label, &sha, NULL, NULL, &client_finished);
    }

    POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->md5));
    POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, md5_digest, MD5_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;

    POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->sha1));
    POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, sha_digest, SHA_DIGEST_LENGTH));
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, NULL, &client_finished);
}

int s2n_prf_server_finished(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);
    POSIX_ENSURE_REF(conn->handshake.hashes);

    struct s2n_blob master_secret, md5, sha;
    uint8_t md5_digest[MD5_DIGEST_LENGTH];
    uint8_t sha_digest[SHA384_DIGEST_LENGTH];
    uint8_t server_finished_label[] = "server finished";
    struct s2n_blob server_finished = {0};
    struct s2n_blob label = {0};

    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_server_finished(conn);
    }

    server_finished.data = conn->handshake.server_finished;
    server_finished.size = S2N_TLS_FINISHED_LEN;
    POSIX_GUARD_RESULT(s2n_handshake_set_finished_len(conn, server_finished.size));
    label.data = server_finished_label;
    label.size = sizeof(server_finished_label) - 1;

    master_secret.data = conn->secrets.tls12.master_secret;
    master_secret.size = sizeof(conn->secrets.tls12.master_secret);
    if (conn->actual_protocol_version == S2N_TLS12) {
        switch (conn->secure->cipher_suite->prf_alg) {
        case S2N_HMAC_SHA256:
            POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->sha256));
            POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, sha_digest, SHA256_DIGEST_LENGTH));
            sha.size = SHA256_DIGEST_LENGTH;
            break;
        case S2N_HMAC_SHA384:
            POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->sha384));
            POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, sha_digest, SHA384_DIGEST_LENGTH));
            sha.size = SHA384_DIGEST_LENGTH;
            break;
        default:
            POSIX_BAIL(S2N_ERR_PRF_INVALID_ALGORITHM);
        }

        sha.data = sha_digest;
        return s2n_prf(conn, &master_secret, &label, &sha, NULL, NULL, &server_finished);
    }

    POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->md5));
    POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, md5_digest, MD5_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;

    POSIX_GUARD(s2n_hash_copy(&conn->handshake.hashes->hash_workspace, &conn->handshake.hashes->sha1));
    POSIX_GUARD(s2n_hash_digest(&conn->handshake.hashes->hash_workspace, sha_digest, SHA_DIGEST_LENGTH));
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, NULL, &server_finished);
}

static int s2n_prf_make_client_key(struct s2n_connection *conn, struct s2n_stuffer *key_material)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);

    struct s2n_blob client_key = {0};
    client_key.size = conn->secure->cipher_suite->record_alg->cipher->key_material_size;
    client_key.data = s2n_stuffer_raw_read(key_material, client_key.size);
    POSIX_ENSURE_REF(client_key.data);

    if (conn->mode == S2N_CLIENT) {
        POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure->client_key, &client_key));
    } else {
        POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure->client_key, &client_key));
    }

    return 0;
}

static int s2n_prf_make_server_key(struct s2n_connection *conn, struct s2n_stuffer *key_material)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);

    struct s2n_blob server_key = {0};
    server_key.size = conn->secure->cipher_suite->record_alg->cipher->key_material_size;
    server_key.data = s2n_stuffer_raw_read(key_material, server_key.size);
    POSIX_ENSURE_REF(server_key.data);

    if (conn->mode == S2N_SERVER) {
        POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure->server_key, &server_key));
    } else {
        POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure->server_key, &server_key));
    }

    return 0;
}

int s2n_prf_key_expansion(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);

    struct s2n_blob client_random = {.data = conn->handshake_params.client_random,.size = sizeof(conn->handshake_params.client_random) };
    struct s2n_blob server_random = {.data = conn->handshake_params.server_random,.size = sizeof(conn->handshake_params.server_random) };
    struct s2n_blob master_secret = {.data = conn->secrets.tls12.master_secret,.size = sizeof(conn->secrets.tls12.master_secret) };
    struct s2n_blob label, out;
    uint8_t key_expansion_label[] = "key expansion";
    uint8_t key_block[S2N_MAX_KEY_BLOCK_LEN];

    label.data = key_expansion_label;
    label.size = sizeof(key_expansion_label) - 1;
    POSIX_GUARD(s2n_blob_init(&out, key_block, sizeof(key_block)));

    struct s2n_stuffer key_material = {0};
    POSIX_GUARD(s2n_prf(conn, &master_secret, &label, &server_random, &client_random, NULL, &out));
    POSIX_GUARD(s2n_stuffer_init(&key_material, &out));
    POSIX_GUARD(s2n_stuffer_write(&key_material, &out));

    POSIX_ENSURE(conn->secure->cipher_suite->available, S2N_ERR_PRF_INVALID_ALGORITHM);
    POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->init(&conn->secure->client_key));
    POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->init(&conn->secure->server_key));

    /* Check that we have a valid MAC and key size */
    uint8_t mac_size;
    if (conn->secure->cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        mac_size = conn->secure->cipher_suite->record_alg->cipher->io.comp.mac_key_size;
    } else {
        POSIX_GUARD(s2n_hmac_digest_size(conn->secure->cipher_suite->record_alg->hmac_alg, &mac_size));
    }

    /* Seed the client MAC */
    uint8_t *client_mac_write_key = s2n_stuffer_raw_read(&key_material, mac_size);
    POSIX_ENSURE_REF(client_mac_write_key);
    POSIX_GUARD(s2n_hmac_reset(&conn->secure->client_record_mac));
    POSIX_GUARD(s2n_hmac_init(&conn->secure->client_record_mac, conn->secure->cipher_suite->record_alg->hmac_alg, client_mac_write_key, mac_size));

    /* Seed the server MAC */
    uint8_t *server_mac_write_key = s2n_stuffer_raw_read(&key_material, mac_size);
    POSIX_ENSURE_REF(server_mac_write_key);
    POSIX_GUARD(s2n_hmac_reset(&conn->secure->server_record_mac));
    POSIX_GUARD(s2n_hmac_init(&conn->secure->server_record_mac, conn->secure->cipher_suite->record_alg->hmac_alg, server_mac_write_key, mac_size));

    /* Make the client key */
    POSIX_GUARD(s2n_prf_make_client_key(conn, &key_material));

    /* Make the server key */
    POSIX_GUARD(s2n_prf_make_server_key(conn, &key_material));

    /* Composite CBC does MAC inside the cipher, pass it the MAC key. 
     * Must happen after setting encryption/decryption keys.
     */
    if (conn->secure->cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->secure->server_key, server_mac_write_key, mac_size));
        POSIX_GUARD(conn->secure->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->secure->client_key, client_mac_write_key, mac_size));
    }

    /* TLS >= 1.1 has no implicit IVs for non AEAD ciphers */
    if (conn->actual_protocol_version > S2N_TLS10 && conn->secure->cipher_suite->record_alg->cipher->type != S2N_AEAD) {
        return 0;
    }

    uint32_t implicit_iv_size = 0;
    switch (conn->secure->cipher_suite->record_alg->cipher->type) {
    case S2N_AEAD:
        implicit_iv_size = conn->secure->cipher_suite->record_alg->cipher->io.aead.fixed_iv_size;
        break;
    case S2N_CBC:
        implicit_iv_size = conn->secure->cipher_suite->record_alg->cipher->io.cbc.block_size;
        break;
    case S2N_COMPOSITE:
        implicit_iv_size = conn->secure->cipher_suite->record_alg->cipher->io.comp.block_size;
        break;
    /* No-op for stream ciphers */
    default:
        break;
    }

    struct s2n_blob client_implicit_iv = {.data = conn->secure->client_implicit_iv,.size = implicit_iv_size };
    struct s2n_blob server_implicit_iv = {.data = conn->secure->server_implicit_iv,.size = implicit_iv_size };
    POSIX_GUARD(s2n_stuffer_read(&key_material, &client_implicit_iv));
    POSIX_GUARD(s2n_stuffer_read(&key_material, &server_implicit_iv));

    return 0;
}
