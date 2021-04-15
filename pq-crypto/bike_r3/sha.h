/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include <openssl/sha.h>
#include "cleanup.h"
#include "error.h"
#include "types.h"
#include "utilities.h"

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

_INLINE_ ret_t sha(OUT sha_dgst_t *  dgst,
                   IN const uint32_t byte_len,
                   IN const uint8_t *msg)
{
  if(SHA384(msg, byte_len, dgst->u.raw) != NULL) {
    return SUCCESS;
  }

  return FAIL;
}

