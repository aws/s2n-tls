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
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "crypto/s2n_evp.h"

#define S2N_MAX_DIGEST_LEN SHA512_DIGEST_LENGTH

typedef enum {
    S2N_HASH_NONE,
    S2N_HASH_MD5,
    S2N_HASH_SHA1,
    S2N_HASH_SHA224,
    S2N_HASH_SHA256,
    S2N_HASH_SHA384,
    S2N_HASH_SHA512,
    S2N_HASH_MD5_SHA1,
    /* Don't add any hash algorithms below S2N_HASH_SENTINEL */
    S2N_HASH_SENTINEL
} s2n_hash_algorithm;

struct s2n_hash_state {
  s2n_hash_algorithm alg;
  int currently_in_hash_block;
};

/* SHA1
 * These fields were determined from the SHA specification, augmented by
 * analyzing SHA implementations.
 * PER_BLOCK_COST is the cost of a compression round.  Pessimistically assume
 * it is 1000 cycles/block, which is worse than real implementations (larger
 * numbers here make lucky13 leakages look worse), and hence large is safer.
 * PER_BYTE_COST is the cost of memcopy one byte that is already in cache,
 * to a location already in cache.
 */
enum {
  PER_BLOCK_COST = 1000,
  PER_BYTE_COST = 1,
  BLOCK_SIZE = 64,
  LENGTH_FIELD_SIZE = 8,
  DIGEST_SIZE = 20
};

#define MAX_SIZE 1024

enum {
  SUCCESS = 0,
  FAILURE = -1
};

int s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out);
int s2n_hash_new(struct s2n_hash_state *state);
S2N_RESULT s2n_hash_state_validate(struct s2n_hash_state *state);
int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg);
int s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size);
int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size);
int s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from);
int s2n_hash_reset(struct s2n_hash_state *state);
int s2n_hash_free(struct s2n_hash_state *state);
int s2n_hash_get_currently_in_hash_total(struct s2n_hash_state *state, uint64_t *out);
