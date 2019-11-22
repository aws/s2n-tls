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

#include <sys/param.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_prf.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

static int s2n_sslv3_prf(struct s2n_prf_working_space *ws, struct s2n_blob *secret, struct s2n_blob *seed_a,
        struct s2n_blob *seed_b, struct s2n_blob *seed_c, struct s2n_blob *out)
{
    struct s2n_hash_state *md5 = &ws->ssl3.md5;
    struct s2n_hash_state *sha1 = &ws->ssl3.sha1;

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;
    uint8_t iteration = 1;

    uint8_t A = 'A';
    while (outputlen) {
        GUARD(s2n_hash_reset(sha1));

        for (int i = 0; i < iteration; i++) {
            GUARD(s2n_hash_update(sha1, &A, 1));
        }

        GUARD(s2n_hash_update(sha1, secret->data, secret->size));
        GUARD(s2n_hash_update(sha1, seed_a->data, seed_a->size));

        if (seed_b) {
            GUARD(s2n_hash_update(sha1, seed_b->data, seed_b->size));
            if (seed_c) {
                GUARD(s2n_hash_update(sha1, seed_c->data, seed_c->size));
            }
        }

        GUARD(s2n_hash_digest(sha1, ws->ssl3.sha1_digest, sizeof(ws->ssl3.sha1_digest)));

        GUARD(s2n_hash_reset(md5));
        GUARD(s2n_hash_update(md5, secret->data, secret->size));
        GUARD(s2n_hash_update(md5, ws->ssl3.sha1_digest, sizeof(ws->ssl3.sha1_digest)));
        GUARD(s2n_hash_digest(md5, ws->ssl3.md5_digest, sizeof(ws->ssl3.md5_digest)));

        uint32_t bytes_to_copy = MIN(outputlen, sizeof(ws->ssl3.md5_digest));

        memcpy_check(output, ws->ssl3.md5_digest, bytes_to_copy);

        outputlen -= bytes_to_copy;
        output += bytes_to_copy;

        /* Increment the letter */
        A++;
        iteration++;
    }

    GUARD(s2n_hash_reset(md5));
    GUARD(s2n_hash_reset(sha1));

    return 0;
}

static int s2n_evp_hmac_p_hash_new(struct s2n_prf_working_space *ws)
{
    notnull_check(ws->tls.p_hash.evp_hmac.evp_digest.ctx = S2N_EVP_MD_CTX_NEW());
    return 0;
}

static int s2n_evp_hmac_p_hash_digest_init(struct s2n_prf_working_space *ws)
{
    notnull_check(ws->tls.p_hash.evp_hmac.evp_digest.md);
    notnull_check(ws->tls.p_hash.evp_hmac.evp_digest.ctx);
    notnull_check(ws->tls.p_hash.evp_hmac.mac_key);
 
    /* Ignore the MD5 check when in FIPS mode to comply with the TLS 1.0 RFC */
    if (s2n_is_in_fips_mode()) {
        GUARD(s2n_digest_allow_md5_for_fips(&ws->tls.p_hash.evp_hmac.evp_digest));
    }

    GUARD_OSSL(EVP_DigestSignInit(ws->tls.p_hash.evp_hmac.evp_digest.ctx, NULL, ws->tls.p_hash.evp_hmac.evp_digest.md, NULL, ws->tls.p_hash.evp_hmac.mac_key),
           S2N_ERR_P_HASH_INIT_FAILED);

    return 0;
}

static int s2n_evp_hmac_p_hash_init(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret)
{
    /* Initialize the message digest */
    switch (alg) {
    case S2N_HMAC_SSLv3_MD5:
    case S2N_HMAC_MD5:
        ws->tls.p_hash.evp_hmac.evp_digest.md = EVP_md5();
        break;
    case S2N_HMAC_SSLv3_SHA1:
    case S2N_HMAC_SHA1:
        ws->tls.p_hash.evp_hmac.evp_digest.md = EVP_sha1();
        break;
    case S2N_HMAC_SHA224:
        ws->tls.p_hash.evp_hmac.evp_digest.md = EVP_sha224();
        break;
    case S2N_HMAC_SHA256:
        ws->tls.p_hash.evp_hmac.evp_digest.md = EVP_sha256();
        break;
    case S2N_HMAC_SHA384:
        ws->tls.p_hash.evp_hmac.evp_digest.md = EVP_sha384();
        break;
    case S2N_HMAC_SHA512:
        ws->tls.p_hash.evp_hmac.evp_digest.md = EVP_sha512();
        break;
    default:
        S2N_ERROR(S2N_ERR_P_HASH_INVALID_ALGORITHM);
    }

    /* Initialize the mac key using the provided secret */
    notnull_check(ws->tls.p_hash.evp_hmac.mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret->data, secret->size));

    /* Initialize the message digest context with the above message digest and mac key */
    return s2n_evp_hmac_p_hash_digest_init(ws);
}

static int s2n_evp_hmac_p_hash_update(struct s2n_prf_working_space *ws, const void *data, uint32_t size)
{
    GUARD_OSSL(EVP_DigestSignUpdate(ws->tls.p_hash.evp_hmac.evp_digest.ctx, data, (size_t)size), S2N_ERR_P_HASH_UPDATE_FAILED);

    return 0;
}

static int s2n_evp_hmac_p_hash_digest(struct s2n_prf_working_space *ws, void *digest, uint32_t size)
{
    /* EVP_DigestSign API's require size_t data structures */
    size_t digest_size = size;

    GUARD_OSSL(EVP_DigestSignFinal(ws->tls.p_hash.evp_hmac.evp_digest.ctx, (unsigned char *)digest, &digest_size), S2N_ERR_P_HASH_FINAL_FAILED);

    return 0;
}

static int s2n_evp_hmac_p_hash_wipe(struct s2n_prf_working_space *ws)
{
  GUARD_OSSL(S2N_EVP_MD_CTX_RESET(ws->tls.p_hash.evp_hmac.evp_digest.ctx), S2N_ERR_P_HASH_WIPE_FAILED);

    return 0;
}

static int s2n_evp_hmac_p_hash_reset(struct s2n_prf_working_space *ws)
{
    GUARD(s2n_evp_hmac_p_hash_wipe(ws));

    return s2n_evp_hmac_p_hash_digest_init(ws);
}

static int s2n_evp_hmac_p_hash_cleanup(struct s2n_prf_working_space *ws)
{
    /* Prepare the workspace md_ctx for the next p_hash */
    GUARD(s2n_evp_hmac_p_hash_wipe(ws));

    /* Free mac key - PKEYs cannot be reused */
    notnull_check(ws->tls.p_hash.evp_hmac.mac_key);
    EVP_PKEY_free(ws->tls.p_hash.evp_hmac.mac_key);
    ws->tls.p_hash.evp_hmac.mac_key = NULL;

    return 0;
}

static int s2n_evp_hmac_p_hash_free(struct s2n_prf_working_space *ws)
{
    notnull_check(ws->tls.p_hash.evp_hmac.evp_digest.ctx);
    S2N_EVP_MD_CTX_FREE(ws->tls.p_hash.evp_hmac.evp_digest.ctx);
    ws->tls.p_hash.evp_hmac.evp_digest.ctx = NULL;

    return 0;
}

static int s2n_hmac_p_hash_new(struct s2n_prf_working_space *ws)
{
    GUARD(s2n_hmac_new(&ws->tls.p_hash.s2n_hmac));

    return s2n_hmac_init(&ws->tls.p_hash.s2n_hmac, S2N_HMAC_NONE, NULL, 0);
}

static int s2n_hmac_p_hash_init(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret)
{
    return s2n_hmac_init(&ws->tls.p_hash.s2n_hmac, alg, secret->data, secret->size);
}

static int s2n_hmac_p_hash_update(struct s2n_prf_working_space *ws, const void *data, uint32_t size)
{
    return s2n_hmac_update(&ws->tls.p_hash.s2n_hmac, data, size);
}

static int s2n_hmac_p_hash_digest(struct s2n_prf_working_space *ws, void *digest, uint32_t size)
{
    return s2n_hmac_digest(&ws->tls.p_hash.s2n_hmac, digest, size);
}

static int s2n_hmac_p_hash_reset(struct s2n_prf_working_space *ws)
{
    return s2n_hmac_reset(&ws->tls.p_hash.s2n_hmac);
}

static int s2n_hmac_p_hash_cleanup(struct s2n_prf_working_space *ws)
{
    return s2n_hmac_p_hash_reset(ws);
}

static int s2n_hmac_p_hash_free(struct s2n_prf_working_space *ws)
{
    return s2n_hmac_free(&ws->tls.p_hash.s2n_hmac);
}

static const struct s2n_p_hash_hmac s2n_evp_hmac = {
    .new = &s2n_evp_hmac_p_hash_new,
    .init = &s2n_evp_hmac_p_hash_init,
    .update = &s2n_evp_hmac_p_hash_update,
    .final = &s2n_evp_hmac_p_hash_digest,
    .reset = &s2n_evp_hmac_p_hash_reset,
    .cleanup = &s2n_evp_hmac_p_hash_cleanup,
    .free = &s2n_evp_hmac_p_hash_free,
};

static const struct s2n_p_hash_hmac s2n_hmac = {
    .new = &s2n_hmac_p_hash_new,
    .init = &s2n_hmac_p_hash_init,
    .update = &s2n_hmac_p_hash_update,
    .final = &s2n_hmac_p_hash_digest,
    .reset = &s2n_hmac_p_hash_reset,
    .cleanup = &s2n_hmac_p_hash_cleanup,
    .free = &s2n_hmac_p_hash_free,
};

static int s2n_p_hash(struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret, struct s2n_blob *label,
                      struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *seed_c, struct s2n_blob *out)
{
    uint8_t digest_size;
    GUARD(s2n_hmac_digest_size(alg, &digest_size));

    const struct s2n_p_hash_hmac *hmac = ws->tls.p_hash_hmac_impl;

    /* First compute hmac(secret + A(0)) */
    GUARD(hmac->init(ws, alg, secret));
    GUARD(hmac->update(ws, label->data, label->size));
    GUARD(hmac->update(ws, seed_a->data, seed_a->size));

    if (seed_b) {
        GUARD(hmac->update(ws, seed_b->data, seed_b->size));
        if (seed_c) {
            GUARD(hmac->update(ws, seed_c->data, seed_c->size));
        }
    }
    GUARD(hmac->final(ws, ws->tls.digest0, digest_size));

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;

    while (outputlen) {
        /* Now compute hmac(secret + A(N - 1) + seed) */
        GUARD(hmac->reset(ws));
        GUARD(hmac->update(ws, ws->tls.digest0, digest_size));

        /* Add the label + seed and compute this round's A */
        GUARD(hmac->update(ws, label->data, label->size));
        GUARD(hmac->update(ws, seed_a->data, seed_a->size));
        if (seed_b) {
            GUARD(hmac->update(ws, seed_b->data, seed_b->size));
            if (seed_c) {
                GUARD(hmac->update(ws, seed_c->data, seed_c->size));
            }
        }

        GUARD(hmac->final(ws, ws->tls.digest1, digest_size));

        uint32_t bytes_to_xor = MIN(outputlen, digest_size);

        for (int i = 0; i < bytes_to_xor; i++) {
            *output ^= ws->tls.digest1[i];
            output++;
            outputlen--;
        }

        /* Stash a digest of A(N), in A(N), for the next round */
        GUARD(hmac->reset(ws));
        GUARD(hmac->update(ws, ws->tls.digest0, digest_size));
        GUARD(hmac->final(ws, ws->tls.digest0, digest_size));
    }

    GUARD(hmac->cleanup(ws));

    return 0;
}

int s2n_prf_new(struct s2n_connection *conn)
{
    /* Set p_hash_hmac_impl on initial prf creation. 
     * When in FIPS mode, the EVP API's must be used for the p_hash HMAC.
     */
    conn->prf_space.tls.p_hash_hmac_impl = s2n_is_in_fips_mode() ? &s2n_evp_hmac : &s2n_hmac;

    return conn->prf_space.tls.p_hash_hmac_impl->new(&conn->prf_space);
}

int s2n_prf_free(struct s2n_connection *conn)
{
    /* Ensure that p_hash_hmac_impl is set, as it may have been reset for prf_space on s2n_connection_wipe. 
     * When in FIPS mode, the EVP API's must be used for the p_hash HMAC.
     */
    conn->prf_space.tls.p_hash_hmac_impl = s2n_is_in_fips_mode() ? &s2n_evp_hmac : &s2n_hmac;

    return conn->prf_space.tls.p_hash_hmac_impl->free(&conn->prf_space);
}

static int s2n_prf(struct s2n_connection *conn, struct s2n_blob *secret, struct s2n_blob *label, struct s2n_blob *seed_a,
                   struct s2n_blob *seed_b, struct s2n_blob *seed_c, struct s2n_blob *out)
{
    /* seed_a is always required, seed_b is optional, if seed_c is provided seed_b must also be provided */
    S2N_ERROR_IF(seed_a == NULL, S2N_ERR_PRF_INVALID_SEED);
    S2N_ERROR_IF(seed_b == NULL && seed_c != NULL, S2N_ERR_PRF_INVALID_SEED);

    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_prf(&conn->prf_space, secret, seed_a, seed_b, seed_c, out);
    }

    /* We zero the out blob because p_hash works by XOR'ing with the existing
     * buffer. This is a little convoluted but means we can avoid dynamic memory
     * allocation. When we call p_hash once (in the TLS1.2 case) it will produce
     * the right values. When we call it twice in the regular case, the two
     * outputs will be XORd just ass the TLS 1.0 and 1.1 RFCs require.
     */
    GUARD(s2n_blob_zero(out));

    /* Ensure that p_hash_hmac_impl is set, as it may have been reset for prf_space on s2n_connection_wipe. 
     * When in FIPS mode, the EVP API's must be used for the p_hash HMAC.
     */
    conn->prf_space.tls.p_hash_hmac_impl = s2n_is_in_fips_mode() ? &s2n_evp_hmac : &s2n_hmac;

    if (conn->actual_protocol_version == S2N_TLS12) {
        return s2n_p_hash(&conn->prf_space, conn->secure.cipher_suite->tls12_prf_alg, secret, label, seed_a, seed_b,
                          seed_c, out);
    }

    struct s2n_blob half_secret = {.data = secret->data,.size = (secret->size + 1) / 2 };

    GUARD(s2n_p_hash(&conn->prf_space, S2N_HMAC_MD5, &half_secret, label, seed_a, seed_b, seed_c, out));
    half_secret.data += secret->size - half_secret.size;
    GUARD(s2n_p_hash(&conn->prf_space, S2N_HMAC_SHA1, &half_secret, label, seed_a, seed_b, seed_c, out));

    return 0;
}

int s2n_tls_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob client_random = {.size = sizeof(conn->secure.client_random), .data = conn->secure.client_random};
    struct s2n_blob server_random = {.size = sizeof(conn->secure.server_random), .data = conn->secure.server_random};
    struct s2n_blob master_secret = {.size = sizeof(conn->secure.master_secret), .data = conn->secure.master_secret};

    uint8_t master_secret_label[] = "master secret";
    struct s2n_blob label = {.size = sizeof(master_secret_label) - 1, .data = master_secret_label};

    return s2n_prf(conn, premaster_secret, &label, &client_random, &server_random, NULL, &master_secret);
}

int s2n_hybrid_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob client_random = {.size = sizeof(conn->secure.client_random), .data = conn->secure.client_random};
    struct s2n_blob server_random = {.size = sizeof(conn->secure.server_random), .data = conn->secure.server_random};
    struct s2n_blob master_secret = {.size = sizeof(conn->secure.master_secret), .data = conn->secure.master_secret};

    uint8_t master_secret_label[] = "hybrid master secret";
    struct s2n_blob label = {.size = sizeof(master_secret_label) - 1, .data = master_secret_label};

    return s2n_prf(conn, premaster_secret, &label, &client_random, &server_random, &conn->secure.client_key_exchange_message, &master_secret);
}

static int s2n_sslv3_finished(struct s2n_connection *conn, uint8_t prefix[4], struct s2n_hash_state *md5, struct s2n_hash_state *sha1, uint8_t * out)
{
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

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.client_finished));

    GUARD(s2n_hash_update(md5, prefix, 4));
    GUARD(s2n_hash_update(md5, conn->secure.master_secret, sizeof(conn->secure.master_secret)));
    GUARD(s2n_hash_update(md5, xorpad1, 48));
    GUARD(s2n_hash_digest(md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(md5));
    GUARD(s2n_hash_update(md5, conn->secure.master_secret, sizeof(conn->secure.master_secret)));
    GUARD(s2n_hash_update(md5, xorpad2, 48));
    GUARD(s2n_hash_update(md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(md5));

    GUARD(s2n_hash_update(sha1, prefix, 4));
    GUARD(s2n_hash_update(sha1, conn->secure.master_secret, sizeof(conn->secure.master_secret)));
    GUARD(s2n_hash_update(sha1, xorpad1, 40));
    GUARD(s2n_hash_digest(sha1, sha_digest, SHA_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(sha1));
    GUARD(s2n_hash_update(sha1, conn->secure.master_secret, sizeof(conn->secure.master_secret)));
    GUARD(s2n_hash_update(sha1, xorpad2, 40));
    GUARD(s2n_hash_update(sha1, sha_digest, SHA_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(sha1, sha_digest, SHA_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(sha1));

    return 0;
}

static int s2n_sslv3_client_finished(struct s2n_connection *conn)
{
    uint8_t prefix[4] = { 0x43, 0x4c, 0x4e, 0x54 };

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.client_finished));
    GUARD(s2n_hash_copy(&conn->handshake.prf_md5_hash_copy, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&conn->handshake.prf_sha1_hash_copy, &conn->handshake.sha1));
    return s2n_sslv3_finished(conn, prefix, &conn->handshake.prf_md5_hash_copy, &conn->handshake.prf_sha1_hash_copy, conn->handshake.client_finished);
}

static int s2n_sslv3_server_finished(struct s2n_connection *conn)
{
    uint8_t prefix[4] = { 0x53, 0x52, 0x56, 0x52 };

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.server_finished));
    GUARD(s2n_hash_copy(&conn->handshake.prf_md5_hash_copy, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&conn->handshake.prf_sha1_hash_copy, &conn->handshake.sha1));
    return s2n_sslv3_finished(conn, prefix, &conn->handshake.prf_md5_hash_copy, &conn->handshake.prf_sha1_hash_copy, conn->handshake.server_finished);
}

int s2n_prf_client_finished(struct s2n_connection *conn)
{
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
    label.data = client_finished_label;
    label.size = sizeof(client_finished_label) - 1;

    master_secret.data = conn->secure.master_secret;
    master_secret.size = sizeof(conn->secure.master_secret);
    if (conn->actual_protocol_version == S2N_TLS12) {
        switch (conn->secure.cipher_suite->tls12_prf_alg) {
        case S2N_HMAC_SHA256:
            GUARD(s2n_hash_copy(&conn->handshake.prf_tls12_hash_copy, &conn->handshake.sha256));
            GUARD(s2n_hash_digest(&conn->handshake.prf_tls12_hash_copy, sha_digest, SHA256_DIGEST_LENGTH));
            sha.size = SHA256_DIGEST_LENGTH;
            break;
        case S2N_HMAC_SHA384:
            GUARD(s2n_hash_copy(&conn->handshake.prf_tls12_hash_copy, &conn->handshake.sha384));
            GUARD(s2n_hash_digest(&conn->handshake.prf_tls12_hash_copy, sha_digest, SHA384_DIGEST_LENGTH));
            sha.size = SHA384_DIGEST_LENGTH;
            break;
        default:
            S2N_ERROR(S2N_ERR_PRF_INVALID_ALGORITHM);
        }

        sha.data = sha_digest;
        return s2n_prf(conn, &master_secret, &label, &sha, NULL, NULL, &client_finished);
    }

    GUARD(s2n_hash_copy(&conn->handshake.prf_md5_hash_copy, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&conn->handshake.prf_sha1_hash_copy, &conn->handshake.sha1));

    GUARD(s2n_hash_digest(&conn->handshake.prf_md5_hash_copy, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(&conn->handshake.prf_sha1_hash_copy, sha_digest, SHA_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, NULL, &client_finished);
}

int s2n_prf_server_finished(struct s2n_connection *conn)
{
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
    label.data = server_finished_label;
    label.size = sizeof(server_finished_label) - 1;

    master_secret.data = conn->secure.master_secret;
    master_secret.size = sizeof(conn->secure.master_secret);
    if (conn->actual_protocol_version == S2N_TLS12) {
        switch (conn->secure.cipher_suite->tls12_prf_alg) {
        case S2N_HMAC_SHA256:
            GUARD(s2n_hash_copy(&conn->handshake.prf_tls12_hash_copy, &conn->handshake.sha256));
            GUARD(s2n_hash_digest(&conn->handshake.prf_tls12_hash_copy, sha_digest, SHA256_DIGEST_LENGTH));
            sha.size = SHA256_DIGEST_LENGTH;
            break;
        case S2N_HMAC_SHA384:
            GUARD(s2n_hash_copy(&conn->handshake.prf_tls12_hash_copy, &conn->handshake.sha384));
            GUARD(s2n_hash_digest(&conn->handshake.prf_tls12_hash_copy, sha_digest, SHA384_DIGEST_LENGTH));
            sha.size = SHA384_DIGEST_LENGTH;
            break;
        default:
            S2N_ERROR(S2N_ERR_PRF_INVALID_ALGORITHM);
        }

        sha.data = sha_digest;
        return s2n_prf(conn, &master_secret, &label, &sha, NULL, NULL, &server_finished);
    }

    GUARD(s2n_hash_copy(&conn->handshake.prf_md5_hash_copy, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&conn->handshake.prf_sha1_hash_copy, &conn->handshake.sha1));

    GUARD(s2n_hash_digest(&conn->handshake.prf_md5_hash_copy, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(&conn->handshake.prf_sha1_hash_copy, sha_digest, SHA_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, NULL, &server_finished);
}

static int s2n_prf_make_client_key(struct s2n_connection *conn, struct s2n_stuffer *key_material)
{
    struct s2n_blob client_key = {0};
    client_key.size = conn->secure.cipher_suite->record_alg->cipher->key_material_size;
    client_key.data = s2n_stuffer_raw_read(key_material, client_key.size);
    notnull_check(client_key.data);

    if (conn->mode == S2N_CLIENT) {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.client_key, &client_key));
    } else {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.client_key, &client_key));
    }

    return 0;
}

static int s2n_prf_make_server_key(struct s2n_connection *conn, struct s2n_stuffer *key_material)
{
    struct s2n_blob server_key = {0};
    server_key.size = conn->secure.cipher_suite->record_alg->cipher->key_material_size;
    server_key.data = s2n_stuffer_raw_read(key_material, server_key.size);
    notnull_check(server_key.data);

    if (conn->mode == S2N_SERVER) {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.server_key, &server_key));
    } else {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.server_key, &server_key));
    }

    return 0;
}

int s2n_prf_key_expansion(struct s2n_connection *conn)
{
    struct s2n_blob client_random = {.data = conn->secure.client_random,.size = sizeof(conn->secure.client_random) };
    struct s2n_blob server_random = {.data = conn->secure.server_random,.size = sizeof(conn->secure.server_random) };
    struct s2n_blob master_secret = {.data = conn->secure.master_secret,.size = sizeof(conn->secure.master_secret) };
    struct s2n_blob label, out;
    uint8_t key_expansion_label[] = "key expansion";
    uint8_t key_block[S2N_MAX_KEY_BLOCK_LEN];

    label.data = key_expansion_label;
    label.size = sizeof(key_expansion_label) - 1;
    out.data = key_block;
    out.size = sizeof(key_block);

    struct s2n_stuffer key_material = {0};
    GUARD(s2n_prf(conn, &master_secret, &label, &server_random, &client_random, NULL, &out));
    GUARD(s2n_stuffer_init(&key_material, &out));
    GUARD(s2n_stuffer_write(&key_material, &out));

    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));

    /* Check that we have a valid MAC and key size */
    uint8_t mac_size;
    if (conn->secure.cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        mac_size = conn->secure.cipher_suite->record_alg->cipher->io.comp.mac_key_size;
    } else {
        GUARD(s2n_hmac_digest_size(conn->secure.cipher_suite->record_alg->hmac_alg, &mac_size));
    }

    /* Seed the client MAC */
    uint8_t *client_mac_write_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(client_mac_write_key);
    GUARD(s2n_hmac_reset(&conn->secure.client_record_mac));
    GUARD(s2n_hmac_init(&conn->secure.client_record_mac, conn->secure.cipher_suite->record_alg->hmac_alg, client_mac_write_key, mac_size));

    /* Seed the server MAC */
    uint8_t *server_mac_write_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(server_mac_write_key);
    GUARD(s2n_hmac_reset(&conn->secure.server_record_mac));
    GUARD(s2n_hmac_init(&conn->secure.server_record_mac, conn->secure.cipher_suite->record_alg->hmac_alg, server_mac_write_key, mac_size));

    /* Make the client key */
    GUARD(s2n_prf_make_client_key(conn, &key_material));

    /* Make the server key */
    GUARD(s2n_prf_make_server_key(conn, &key_material));

    /* Composite CBC does MAC inside the cipher, pass it the MAC key. 
     * Must happen after setting encryption/decryption keys.
     */
    if (conn->secure.cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->secure.server_key, server_mac_write_key, mac_size));
        GUARD(conn->secure.cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->secure.client_key, client_mac_write_key, mac_size));
    }

    /* TLS >= 1.1 has no implicit IVs for non AEAD ciphers */
    if (conn->actual_protocol_version > S2N_TLS10 && conn->secure.cipher_suite->record_alg->cipher->type != S2N_AEAD) {
        return 0;
    }

    uint32_t implicit_iv_size = 0;
    switch (conn->secure.cipher_suite->record_alg->cipher->type) {
    case S2N_AEAD:
        implicit_iv_size = conn->secure.cipher_suite->record_alg->cipher->io.aead.fixed_iv_size;
        break;
    case S2N_CBC:
        implicit_iv_size = conn->secure.cipher_suite->record_alg->cipher->io.cbc.block_size;
        break;
    case S2N_COMPOSITE:
        implicit_iv_size = conn->secure.cipher_suite->record_alg->cipher->io.comp.block_size;
        break;
    /* No-op for stream ciphers */
    default:
        break;
    }

    struct s2n_blob client_implicit_iv = {.data = conn->secure.client_implicit_iv,.size = implicit_iv_size };
    struct s2n_blob server_implicit_iv = {.data = conn->secure.server_implicit_iv,.size = implicit_iv_size };
    GUARD(s2n_stuffer_read(&key_material, &client_implicit_iv));
    GUARD(s2n_stuffer_read(&key_material, &server_implicit_iv));

    return 0;
}
