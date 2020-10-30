/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#include "sampling.h"
#include <assert.h>

#define MAX_WEIGHT (T1 > DV ? T1 : DV)

// This implementation assumes that the wlist contains fake list
void
secure_set_bits(IN OUT uint64_t * a,
                IN const idx_t    wlist[],
                IN const uint32_t a_len_bytes,
                IN const uint32_t weight)
{
  assert(a_len_bytes % 8 == 0);

  // Set arrays to the maximum possible for the stack protector
  assert(weight <= MAX_WEIGHT);
  uint64_t qw_pos[MAX_WEIGHT];
  uint64_t bit_pos[MAX_WEIGHT];

  // 1. Identify the QW position of each value and the bit position inside this
  // QW.
  for(uint32_t j = 0; j < weight; j++)
  {
    qw_pos[j]  = wlist[j] >> 6;
    bit_pos[j] = BIT(wlist[j] & 0x3f);
  }

  // 2. Fill each QW in a constant time.
  for(uint32_t qw = 0; qw < (a_len_bytes / 8); qw++)
  {
    uint64_t tmp = 0;
    for(uint32_t j = 0; j < weight; j++)
    {
      uint64_t mask = (-1ULL) + (!secure_cmp32(qw_pos[j], qw));
      tmp |= (bit_pos[j] & mask);
    }
    // Set the bit in a masked way
    a[qw] |= tmp;
  }
}
