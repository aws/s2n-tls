/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include <inttypes.h>

#include "utilities.h"

#define BITS_IN_QWORD 64ULL
#define BITS_IN_BYTE  8ULL

uint64_t r_bits_vector_weight(IN const r_t *in)
{
  uint64_t acc = 0;
  for(size_t i = 0; i < (R_BYTES - 1); i++) {
    acc += __builtin_popcount(in->raw[i]);
  }

  acc += __builtin_popcount(in->raw[R_BYTES - 1] & LAST_R_BYTE_MASK);
  return acc;
}
