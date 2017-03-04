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

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

static int s2n_sslv3_prf(union s2n_prf_working_space *ws, struct s2n_blob *secret, struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *out)
{
    struct s2n_hash_state *md5 = &ws->ssl3.md5;
    struct s2n_hash_state *sha1 = &ws->ssl3.sha1;

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;
    uint8_t iteration = 1;

    uint8_t A = 'A';
    while (outputlen) {
        GUARD(s2n_hash_init(sha1, S2N_HASH_SHA1));

        for (int i = 0; i < iteration; i++) {
            GUARD(s2n_hash_update(sha1, &A, 1));
        }

        GUARD(s2n_hash_update(sha1, secret->data, secret->size));
        GUARD(s2n_hash_update(sha1, seed_a->data, seed_a->size));

        if (seed_b) {
            GUARD(s2n_hash_update(sha1, seed_b->data, seed_b->size));
        }

        GUARD(s2n_hash_digest(sha1, ws->ssl3.sha1_digest, sizeof(ws->ssl3.sha1_digest)));
        GUARD(s2n_hash_init(md5, S2N_HASH_MD5));
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

    return 0;
}

static int s2n_p_hash(union s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret,
                      struct s2n_blob *label, struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *out)
{
    struct s2n_hmac_state *hmac = &ws->tls.hmac;
    uint8_t digest_size;
    GUARD(s2n_hmac_digest_size(alg, &digest_size));

    /* First compute hmac(secret + A(0)) */
    GUARD(s2n_hmac_init(hmac, alg, secret->data, secret->size));
    GUARD(s2n_hmac_update(hmac, label->data, label->size));
    GUARD(s2n_hmac_update(hmac, seed_a->data, seed_a->size));

    if (seed_b) {
        GUARD(s2n_hmac_update(hmac, seed_b->data, seed_b->size));
    }
    GUARD(s2n_hmac_digest(hmac, ws->tls.digest0, digest_size));

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;

    while (outputlen) {
        /* Now compute hmac(secret + A(N - 1) + seed) */
        GUARD(s2n_hmac_reset(hmac));
        GUARD(s2n_hmac_update(hmac, ws->tls.digest0, digest_size));

        /* Add the label + seed and compute this round's A */
        GUARD(s2n_hmac_update(hmac, label->data, label->size));
        GUARD(s2n_hmac_update(hmac, seed_a->data, seed_a->size));
        if (seed_b) {
            GUARD(s2n_hmac_update(hmac, seed_b->data, seed_b->size));
        }
        GUARD(s2n_hmac_digest(hmac, ws->tls.digest1, digest_size));

        uint32_t bytes_to_xor = MIN(outputlen, digest_size);

        for (int i = 0; i < bytes_to_xor; i++) {
            *output ^= ws->tls.digest1[i];
            output++;
            outputlen--;
        }

        /* Stash a digest of A(N), in A(N), for the next round */
        GUARD(s2n_hmac_reset(hmac));
        GUARD(s2n_hmac_update(hmac, ws->tls.digest0, digest_size));
        GUARD(s2n_hmac_digest(hmac, ws->tls.digest0, digest_size));
    }

    return 0;
}

static int s2n_prf(struct s2n_connection *conn, struct s2n_blob *secret, struct s2n_blob *label, struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *out)
{
    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_prf(&conn->prf_space, secret, seed_a, seed_b, out);
    }

    /* We zero the out blob because p_hash works by XOR'ing with the existing
     * buffer. This is a little convoluted but means we can avoid dynamic memory
     * allocation. When we call p_hash once (in the TLS1.2 case) it will produce
     * the right values. When we call it twice in the regular case, the two
     * outputs will be XORd just ass the TLS 1.0 and 1.1 RFCs require.
     */
    GUARD(s2n_blob_zero(out));

    if (conn->actual_protocol_version == S2N_TLS12) {
        return s2n_p_hash(&conn->prf_space, conn->secure.cipher_suite->tls12_prf_alg, secret, label, seed_a, seed_b, out);
    }

    struct s2n_blob half_secret = {.data = secret->data,.size = (secret->size + 1) / 2 };

    GUARD(s2n_p_hash(&conn->prf_space, S2N_HMAC_MD5, &half_secret, label, seed_a, seed_b, out));
    half_secret.data += secret->size - half_secret.size;
    GUARD(s2n_p_hash(&conn->prf_space, S2N_HMAC_SHA1, &half_secret, label, seed_a, seed_b, out));

    return 0;
}

int s2n_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob client_random, server_random, master_secret;
    struct s2n_blob label;
    uint8_t master_secret_label[] = "master secret";

    client_random.data = conn->secure.client_random;
    client_random.size = sizeof(conn->secure.client_random);
    server_random.data = conn->secure.server_random;
    server_random.size = sizeof(conn->secure.server_random);
    master_secret.data = conn->secure.master_secret;
    master_secret.size = sizeof(conn->secure.master_secret);
    label.data = master_secret_label;
    label.size = sizeof(master_secret_label) - 1;

    return s2n_prf(conn, premaster_secret, &label, &client_random, &server_random, &master_secret);
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
    struct s2n_hash_state md5, sha1;

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.client_finished));
    GUARD(s2n_hash_copy(&md5, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&sha1, &conn->handshake.sha1));
    return s2n_sslv3_finished(conn, prefix, &md5, &sha1, conn->handshake.client_finished);
}

static int s2n_sslv3_server_finished(struct s2n_connection *conn)
{
    uint8_t prefix[4] = { 0x53, 0x52, 0x56, 0x52 };
    struct s2n_hash_state md5, sha1;

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.server_finished));
    GUARD(s2n_hash_copy(&md5, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&sha1, &conn->handshake.sha1));
    return s2n_sslv3_finished(conn, prefix, &md5, &sha1, conn->handshake.server_finished);
}

int s2n_prf_client_finished(struct s2n_connection *conn)
{
    struct s2n_blob master_secret, md5, sha;
    uint8_t md5_digest[MD5_DIGEST_LENGTH];
    uint8_t sha_digest[SHA384_DIGEST_LENGTH];
    uint8_t client_finished_label[] = "client finished";
    struct s2n_blob client_finished;
    struct s2n_blob label;

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
        struct s2n_hash_state hash_state;
        switch (conn->secure.cipher_suite->tls12_prf_alg) {
        case S2N_HMAC_SHA256:
            GUARD(s2n_hash_copy(&hash_state, &conn->handshake.sha256));
            GUARD(s2n_hash_digest(&hash_state, sha_digest, SHA256_DIGEST_LENGTH));
            sha.size = SHA256_DIGEST_LENGTH;
            break;
        case S2N_HMAC_SHA384:
            GUARD(s2n_hash_copy(&hash_state, &conn->handshake.sha384));
            GUARD(s2n_hash_digest(&hash_state, sha_digest, SHA384_DIGEST_LENGTH));
            sha.size = SHA384_DIGEST_LENGTH;
            break;
        default:
            S2N_ERROR(S2N_ERR_PRF_INVALID_ALGORITHM);
        }

        sha.data = sha_digest;
        return s2n_prf(conn, &master_secret, &label, &sha, NULL, &client_finished);
    }

    struct s2n_hash_state md5_state, sha1_state;
    GUARD(s2n_hash_copy(&md5_state, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&sha1_state, &conn->handshake.sha1));

    GUARD(s2n_hash_digest(&md5_state, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(&sha1_state, sha_digest, SHA_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, &client_finished);
}

int s2n_prf_server_finished(struct s2n_connection *conn)
{
    struct s2n_blob master_secret, md5, sha;
    uint8_t md5_digest[MD5_DIGEST_LENGTH];
    uint8_t sha_digest[SHA384_DIGEST_LENGTH];
    uint8_t server_finished_label[] = "server finished";
    struct s2n_blob server_finished;
    struct s2n_blob label;

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
        struct s2n_hash_state hash_state;
        switch (conn->secure.cipher_suite->tls12_prf_alg) {
        case S2N_HMAC_SHA256:
            GUARD(s2n_hash_copy(&hash_state, &conn->handshake.sha256));
            GUARD(s2n_hash_digest(&hash_state, sha_digest, SHA256_DIGEST_LENGTH));
            sha.size = SHA256_DIGEST_LENGTH;
            break;
        case S2N_HMAC_SHA384:
            GUARD(s2n_hash_copy(&hash_state, &conn->handshake.sha384));
            GUARD(s2n_hash_digest(&hash_state, sha_digest, SHA384_DIGEST_LENGTH));
            sha.size = SHA384_DIGEST_LENGTH;
            break;
        default:
            S2N_ERROR(S2N_ERR_PRF_INVALID_ALGORITHM);
        }

        sha.data = sha_digest;
        return s2n_prf(conn, &master_secret, &label, &sha, NULL, &server_finished);
    }

    struct s2n_hash_state md5_state, sha1_state;
    GUARD(s2n_hash_copy(&md5_state, &conn->handshake.md5));
    GUARD(s2n_hash_copy(&sha1_state, &conn->handshake.sha1));

    GUARD(s2n_hash_digest(&md5_state, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(&sha1_state, sha_digest, SHA_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, &server_finished);
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

    struct s2n_stuffer key_material;
    GUARD(s2n_prf(conn, &master_secret, &label, &server_random, &client_random, &out));
    GUARD(s2n_stuffer_init(&key_material, &out));
    GUARD(s2n_stuffer_write(&key_material, &out));

    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));

    /* What's our hmac algorithm? */
    s2n_hmac_algorithm hmac_alg = conn->secure.cipher_suite->record_alg->hmac_alg;
    if (conn->actual_protocol_version == S2N_SSLv3) {
        if (hmac_alg == S2N_HMAC_SHA1) {
            hmac_alg = S2N_HMAC_SSLv3_SHA1;
        } else if (hmac_alg == S2N_HMAC_MD5) {
            hmac_alg = S2N_HMAC_SSLv3_MD5;
        } else {
            S2N_ERROR(S2N_ERR_HMAC_INVALID_ALGORITHM);
        }
    }

    /* Check that we have a valid MAC and key size */
    uint8_t mac_size;
    if (conn->secure.cipher_suite->record_alg->cipher->type == S2N_COMPOSITE) {
        mac_size = conn->secure.cipher_suite->record_alg->cipher->io.comp.mac_key_size;
    } else {
        GUARD(s2n_hmac_digest_size(hmac_alg, &mac_size));
    }

    /* Seed the client MAC */
    uint8_t *client_mac_write_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(client_mac_write_key);
    GUARD(s2n_hmac_init(&conn->secure.client_record_mac, hmac_alg, client_mac_write_key, mac_size));

    /* Seed the server MAC */
    uint8_t *server_mac_write_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(server_mac_write_key);
    GUARD(s2n_hmac_init(&conn->secure.server_record_mac, hmac_alg, server_mac_write_key, mac_size));

    /* Make the client key */
    struct s2n_blob client_key;
    client_key.size = conn->secure.cipher_suite->record_alg->cipher->key_material_size;
    client_key.data = s2n_stuffer_raw_read(&key_material, client_key.size);
    notnull_check(client_key.data);
    if (conn->mode == S2N_CLIENT) {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.client_key, &client_key));
    } else {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.client_key, &client_key));
    }

    /* Make the server key */
    struct s2n_blob server_key;
    server_key.size = conn->secure.cipher_suite->record_alg->cipher->key_material_size;
    server_key.data = s2n_stuffer_raw_read(&key_material, server_key.size);
    notnull_check(server_key.data);
    
    if (conn->mode == S2N_SERVER) {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.server_key, &server_key));
    } else {
        GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.server_key, &server_key));
    }

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
