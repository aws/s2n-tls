/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "parallel_hash.h"
#include "utilities.h"
#include <assert.h>
#include <string.h>

#define MAX_REM_LEN (MAX_MB_SLICES * HASH_BLOCK_SIZE)

// We must ensure that the compiler does not add padding between x and y, because
// the entire structore goes into the hash function.
#pragma pack(push, 1)

// The struct below is a concatination of eight slices and Y.
typedef struct yx_s
{
  sha_hash_t x[MAX_MB_SLICES];
  // We define MAX_REM_LEN rather than lrem, in order to be consistent with the
  // standard of C.
  uint8_t y[MAX_REM_LEN];
} yx_t;

#pragma pack(pop)

_INLINE_ uint64_t
compute_slice_len(IN const uint64_t la)
{
  assert((la / MAX_MB_SLICES) >= SLICE_REM);

  // alpha is the number of full blocks
  const uint64_t alpha = (((la / MAX_MB_SLICES) - SLICE_REM) / HASH_BLOCK_SIZE);
  return ((alpha * HASH_BLOCK_SIZE) + SLICE_REM);
}

// This function assumes that m is of N_BITS length.
void
parallel_hash(OUT sha_hash_t *out_hash, IN const uint8_t *m, IN const uint32_t la)
{
  DMSG("    Enter parallel_hash.\n");

  // Calculating how many bytes will go to "parallel" hashing
  // and how many will remind as a tail for later on
  const uint32_t ls   = compute_slice_len(la);
  const uint32_t lrem = (uint32_t)(la - (ls * MAX_MB_SLICES));
  yx_t           yx   = {0};

#ifdef WIN32
  DMSG("    Len=%u splits into %I64u logical streams (A1..A8) of length %u "
       "bytes. ",
       la, MAX_MB_SLICES, ls);
  DMSG("Append the logically remaining buffer (Y) of %u - %I64u*%u = %u "
       "bytes\n\n",
       la, MAX_MB_SLICES, ls, lrem);
#else
  DMSG("    Len=%u splits into %llu logical streams (A1..A8) of length %u "
       "bytes. ",
       la, MAX_MB_SLICES, ls);
  DMSG("Append the logically remaining buffer (Y) of %u - %llu*%u = %u "
       "bytes\n\n",
       la, MAX_MB_SLICES, ls, lrem);
#endif

  print("    The (original) buffer is:\n    ", (const uint64_t *)m, la * 8);
  DMSG("\n");
  EDMSG("    The 8 SHA digests:\n");

  // Use optimized API for 4 blocks.
  const uint64_t partial_len = (NUM_OF_BLOCKS_IN_MB * ls);
  sha_mb(&yx.x[0], m, partial_len, NUM_OF_BLOCKS_IN_MB);
#if NUM_OF_BLOCKS_IN_MB != MAX_MB_SLICES
  sha_mb(&yx.x[NUM_OF_BLOCKS_IN_MB], &m[partial_len], partial_len,
         NUM_OF_BLOCKS_IN_MB);
#endif

  for(uint32_t i = 0; i < MAX_MB_SLICES; i++)
  {
    print("X[i]:", (uint64_t *)&yx.x[i], SIZEOF_BITS(yx.x[i]));
  }

  // Copy the reminder (Y)
  memcpy(yx.y, &m[MAX_MB_SLICES * ls], lrem);

  // Compute the final hash (on YX). We explicitly use lrem instead of
  // sizeof(yx.y) because yx.y is padded with zeros.
  sha(out_hash, sizeof(yx.x) + lrem, (uint8_t *)&yx);

  print("\nY:  ", (uint64_t *)yx.y, lrem * 8);

  // yx might contain secrets
  secure_clean((uint8_t *)&yx, sizeof(yx));

  DMSG("    Exit parallel_hash.\n");
}
