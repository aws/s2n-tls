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
#include "tls/s2n_connection.h"
#include "utils/s2n_blob.h"

/* Enough to support TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 2*SHA384_DIGEST_LEN + 2*AES256_KEY_SIZE */
#define S2N_MAX_KEY_BLOCK_LEN 160

union p_hash_state {
    struct s2n_hmac_state s2n_hmac;
};

/* TLS 1.2 PRF scratch space. p_hash, digest0, and digest1 are all live
 * simultaneously within a single s2n_p_hash() computation, so they can't
 * overlap each other. */
struct s2n_prf_tls12_space {
    union p_hash_state p_hash;
    uint8_t digest0[S2N_MAX_DIGEST_LEN];
    uint8_t digest1[S2N_MAX_DIGEST_LEN];
};

/* Reusable contexts for the TLS 1.3 key schedule.
 * Allocated once on first key-schedule use, reset (init) per derivation, and
 * freed once with the workspace. */
struct s2n_prf_tls13_space {
    struct s2n_hmac_state tls13_hmac;
    struct s2n_hash_state tls13_hash;
};

/* Tracks which version-specific scratch space in s2n_prf_working_space->space
 * has been allocated. A connection uses either the TLS 1.2 PRF or the TLS 1.3
 * key schedule, never both, so only one side is ever allocated. The contexts
 * are heap-backed (EVP_MD_CTX), so we must know which side is live in order to
 * free and wipe exactly the allocated contexts. */
typedef enum {
    S2N_PRF_SPACE_UNALLOCATED = 0,
    S2N_PRF_SPACE_TLS12,
    S2N_PRF_SPACE_TLS13,
} s2n_prf_space_type;

/* A connection uses either the TLS 1.2 PRF or the TLS 1.3 key schedule, never
 * both, so the two scratch spaces safely overlap in the space union. The
 * contexts within are allocated lazily (only the negotiated side is ever
 * allocated) and `allocated` records which side that is. */
struct s2n_prf_working_space {
    union {
        struct s2n_prf_tls12_space tls12;
        struct s2n_prf_tls13_space tls13;
    } space;
    s2n_prf_space_type allocated;
};

/* TLS key expansion results in an array of contiguous data which is then
 * interpreted as the MAC, KEY and IV for the client and server.
 *
 * The following is the memory layout of the key material:
 *
 *     [ CLIENT_MAC, SERVER_MAC, CLIENT_KEY, SERVER_KEY, CLIENT_IV, SERVER_IV ]
 */
struct s2n_key_material {
    /* key material data resulting from key expansion */
    uint8_t key_block[S2N_MAX_KEY_BLOCK_LEN];

    /* pointers into data representing specific key information */
    struct s2n_blob client_mac;
    struct s2n_blob server_mac;
    struct s2n_blob client_key;
    struct s2n_blob server_key;
    struct s2n_blob client_iv;
    struct s2n_blob server_iv;
};

S2N_RESULT s2n_key_material_init(struct s2n_key_material *key_material, struct s2n_connection *conn);

S2N_RESULT s2n_prf_new(struct s2n_connection *conn);
S2N_RESULT s2n_prf_wipe(struct s2n_connection *conn);
S2N_RESULT s2n_prf_free(struct s2n_connection *conn);

/* Lazily allocates the per-connection prf_space workspace and its reusable
 * TLS 1.3 key-schedule contexts (tls13_hmac/tls13_hash) on first use, then
 * returns the workspace via the out-param. Centralizes the lazy-allocation rule
 * so the TLS 1.3 key-schedule derivation sites can obtain an
 * allocated workspace without duplicating the allocation logic. The returned
 * workspace has its TLS 1.3 scratch space allocated (allocated == TLS13). */
S2N_RESULT s2n_connection_get_prf_space(struct s2n_connection *conn, struct s2n_prf_working_space **ws);

int s2n_prf_calculate_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret);
int s2n_prf_hybrid_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret);
S2N_RESULT s2n_prf_generate_key_material(struct s2n_connection *conn, struct s2n_key_material *key_material);
int s2n_prf_key_expansion(struct s2n_connection *conn);
int s2n_prf_server_finished(struct s2n_connection *conn);
int s2n_prf_client_finished(struct s2n_connection *conn);
