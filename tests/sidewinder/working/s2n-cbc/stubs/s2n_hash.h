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

//SHA1
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

extern int s2n_hash_digest_size(s2n_hash_algorithm alg, uint8_t *out);
extern int s2n_hash_new(struct s2n_hash_state *state);
extern int s2n_hash_init(struct s2n_hash_state *state, s2n_hash_algorithm alg);
extern int s2n_hash_update(struct s2n_hash_state *state, const void *data, uint32_t size);
extern int s2n_hash_digest(struct s2n_hash_state *state, void *out, uint32_t size);
extern int s2n_hash_copy(struct s2n_hash_state *to, struct s2n_hash_state *from);
extern int s2n_hash_reset(struct s2n_hash_state *state);
extern int s2n_hash_free(struct s2n_hash_state *state);


