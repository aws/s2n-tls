/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "sampling.h"
#include <assert.h>

#define MAX_WEIGHT (T1 > FAKE_DV ? T1 : FAKE_DV)

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
  uint64_t tmp = 0;

  // 1. Identify the QW position of eav value and the bit position inside this QW.
  for(uint32_t j = 0; j < weight; j++)
  {
    qw_pos[j]  = wlist[j].val >> 6;
    bit_pos[j] = BIT(wlist[j].val & 0x3f);
  }

  // 2. Fill each QW in a constant time.
  for(uint32_t qw = 0; qw < (a_len_bytes / 8); qw++)
  {
    tmp = 0;
    for(uint32_t j = 0; j < weight; j++)
    {
      uint64_t mask = (-1ULL) + (!secure_cmp32(qw_pos[j], qw));
      mask &= (-1ULL) + (wlist[j].used + 1U);
      tmp |= (bit_pos[j] & mask);
    }
    // Set the bit in a masked way
    a[qw] |= tmp;
  }
}
