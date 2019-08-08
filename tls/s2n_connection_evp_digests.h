/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_connection.h"
#include "tls/s2n_prf.h"

#include "crypto/s2n_hash.h"

struct s2n_connection_prf_handles {
    /* TLS PRF HMAC p_hash */
    struct s2n_hmac_evp_backup p_hash_s2n_hmac;

    /* TLS PRF EVP p_hash */
    struct s2n_evp_hmac_state p_hash_evp_hmac;
};

struct s2n_connection_hash_handles {
    /* Handshake hash states */
    struct s2n_hash_evp_digest md5;
    struct s2n_hash_evp_digest sha1;
    struct s2n_hash_evp_digest sha224;
    struct s2n_hash_evp_digest sha256;
    struct s2n_hash_evp_digest sha384;
    struct s2n_hash_evp_digest sha512;
    struct s2n_hash_evp_digest md5_sha1;
    struct s2n_hash_evp_digest ccv_hash_copy;
    struct s2n_hash_evp_digest prf_md5_hash_copy;
    struct s2n_hash_evp_digest prf_sha1_hash_copy;
    struct s2n_hash_evp_digest prf_tls12_hash_copy;
    struct s2n_hash_evp_digest prf_md5;

    /* SSLv3 PRF hash states */
    struct s2n_hash_evp_digest prf_sha1;

    /* Initial signature hash states */
    struct s2n_hash_evp_digest initial_signature_hash;
    struct s2n_hash_evp_digest secure_signature_hash;
};

/* Allocationg new EVP structs is expensive, so we back them up here and reuse them */
struct s2n_connection_hmac_handles {
    struct s2n_hmac_evp_backup initial_client;
    struct s2n_hmac_evp_backup initial_client_copy;
    struct s2n_hmac_evp_backup initial_server;
    struct s2n_hmac_evp_backup secure_client;
    struct s2n_hmac_evp_backup secure_client_copy;
    struct s2n_hmac_evp_backup secure_server;
};

extern int s2n_connection_save_prf_state(struct s2n_connection_prf_handles *prf_handles, struct s2n_connection *conn);
extern int s2n_connection_save_hash_state(struct s2n_connection_hash_handles *hash_handles, struct s2n_connection *conn);
extern int s2n_connection_save_hmac_state(struct s2n_connection_hmac_handles *hmac_handles, struct s2n_connection *conn);
extern int s2n_connection_restore_prf_state(struct s2n_connection *conn, struct s2n_connection_prf_handles *prf_handles);
extern int s2n_connection_restore_hash_state(struct s2n_connection *conn, struct s2n_connection_hash_handles *hash_handles);
extern int s2n_connection_restore_hmac_state(struct s2n_connection *conn, struct s2n_connection_hmac_handles *hmac_handles);
