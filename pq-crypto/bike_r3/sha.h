/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "cleanup.h"
#include "error.h"
#include "types.h"

#define SHA384_DGST_BYTES  48ULL
#define SHA384_DGST_QWORDS (SHA384_DGST_BYTES / 8)

#define SHA512_DGST_BYTES  64ULL
#define SHA512_DGST_QWORDS (SHA512_DGST_BYTES / 8)

typedef struct sha384_dgst_s {
  union {
    uint8_t  raw[SHA384_DGST_BYTES];
    uint64_t qw[SHA384_DGST_QWORDS];
  } u;
} sha384_dgst_t;
bike_static_assert(sizeof(sha384_dgst_t) == SHA384_DGST_BYTES, sha384_dgst_size);

typedef sha384_dgst_t sha_dgst_t;
CLEANUP_FUNC(sha_dgst, sha_dgst_t)

#if defined(USE_OPENSSL)

#  include "utilities.h"
#  include <openssl/sha.h>

_INLINE_ ret_t sha(OUT sha_dgst_t *  dgst,
                   IN const uint32_t byte_len,
                   IN const uint8_t *msg)
{
  if(SHA384(msg, byte_len, dgst->u.raw) != NULL) {
    return SUCCESS;
  }

  return FAIL;
}

#else // USE_OPENSSL

#  define HASH_BLOCK_BYTES 128ULL

typedef struct sha512_dgst_s {
  union {
    uint8_t  raw[SHA512_DGST_BYTES];
    uint64_t qw[SHA512_DGST_QWORDS];
  } u;
} sha512_dgst_t;
bike_static_assert(sizeof(sha512_dgst_t) == SHA512_DGST_BYTES, sha512_dgst_size);

ret_t sha(OUT sha_dgst_t *dgst, IN uint32_t byte_len, IN const uint8_t *msg);

#endif // USE_OPENSSL
