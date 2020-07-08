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

#pragma once

#include <stdint.h>

#include "crypto/s2n_hash.h"
#include "crypto/s2n_hmac.h"
#include "crypto/s2n_openssl.h"

#include "utils/s2n_blob.h"

/* Enough to support TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 2*SHA384_DIGEST_LEN + 2*AES256_KEY_SIZE */
#define S2N_MAX_KEY_BLOCK_LEN 160

struct p_hash_state {
    struct s2n_hmac_state s2n_hmac;
    struct s2n_evp_hmac_state evp_hmac;
};

struct s2n_prf_working_space {
    struct {
        const struct s2n_p_hash_hmac *p_hash_hmac_impl;
        struct p_hash_state p_hash;
        uint8_t digest0[S2N_MAX_DIGEST_LEN];
        uint8_t digest1[S2N_MAX_DIGEST_LEN];
    } tls;

    struct {
        struct s2n_hash_state md5;
        struct s2n_hash_state sha1;
        uint8_t md5_digest[MD5_DIGEST_LENGTH];
        uint8_t sha1_digest[SHA_DIGEST_LENGTH];
    } ssl3;
};

/* The s2n p_hash implementation is abstracted to allow for separate implementations, using
 * either s2n's formally verified HMAC or OpenSSL's EVP HMAC, for use by the TLS PRF. */
struct s2n_p_hash_hmac {
    int (*alloc) (struct s2n_prf_working_space *ws);
    int (*init) (struct s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret);
    int (*update) (struct s2n_prf_working_space *ws, const void *data, uint32_t size);
    int (*final) (struct s2n_prf_working_space *ws, void *digest, uint32_t size);
    int (*reset) (struct s2n_prf_working_space *ws);
    int (*cleanup) (struct s2n_prf_working_space *ws);
    int (*free) (struct s2n_prf_working_space *ws);
};

#include "tls/s2n_connection.h"

extern int s2n_prf_new(struct s2n_connection *conn);
extern int s2n_prf_free(struct s2n_connection *conn);
extern int s2n_tls_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret);
extern int s2n_hybrid_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret);
extern int s2n_prf_key_expansion(struct s2n_connection *conn);
extern int s2n_prf_server_finished(struct s2n_connection *conn);
extern int s2n_prf_client_finished(struct s2n_connection *conn);
