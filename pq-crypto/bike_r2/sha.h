/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * The license is detailed in the file LICENSE.md, and applies to this file.
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

#include "cleanup.h"
#include "types.h"
#include "utilities.h"
#include <openssl/sha.h>

#define SHA384_HASH_SIZE   48ULL
#define SHA384_HASH_QWORDS (SHA384_HASH_SIZE / 8)

typedef struct sha384_hash_s
{
  union {
    uint8_t  raw[SHA384_HASH_SIZE];
    uint64_t qw[SHA384_HASH_QWORDS];
  } u;
} sha384_hash_t;
bike_static_assert(sizeof(sha384_hash_t) == SHA384_HASH_SIZE, sha384_hash_size);

typedef sha384_hash_t sha_hash_t;

_INLINE_ void
sha_hash_cleanup(IN OUT sha_hash_t *o)
{
  secure_clean(o->u.raw, sizeof(*o));
}

_INLINE_ int
sha(OUT sha_hash_t *hash_out, IN const uint32_t byte_len, IN const uint8_t *msg)
{
  SHA384(msg, byte_len, hash_out->u.raw);
  return 1;
}
