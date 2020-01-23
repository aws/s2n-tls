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

#include "sampling.h"
#include <assert.h>
#include <string.h>

_INLINE_ ret_t
get_rand_mod_len(OUT uint32_t *    rand_pos,
                 IN const uint32_t len,
                 IN OUT aes_ctr_prf_state_t *prf_state)
{
  const uint64_t mask = MASK(bit_scan_reverse(len));

  do
  {
    // Generate 128bit of random numbers
    GUARD(aes_ctr_prf((uint8_t *)rand_pos, prf_state, sizeof(*rand_pos)));

    // Mask only relevant bits
    (*rand_pos) &= mask;

    // Break if a number smaller than len is found
    if((*rand_pos) < len)
    {
      break;
    }

  } while(1 == 1);

  return SUCCESS;
}

_INLINE_ void
make_odd_weight(IN OUT r_t *r)
{
  if(((r_bits_vector_weight(r) % 2) == 1))
  {
    // Already odd
    return;
  }

  r->raw[0] ^= 1;
}

// IN: must_be_odd - 1 true, 0 not
ret_t
sample_uniform_r_bits_with_fixed_prf_context(OUT r_t *r,
                                             IN OUT
                                                 aes_ctr_prf_state_t *prf_state,
                                             IN const must_be_odd_t   must_be_odd)
{
  // Generate random data
  GUARD(aes_ctr_prf(r->raw, prf_state, R_SIZE));

  // Mask upper bits of the MSByte
  r->raw[R_SIZE - 1] &= MASK(R_BITS + 8 - (R_SIZE * 8));

  if(must_be_odd == MUST_BE_ODD)
  {
    make_odd_weight(r);
  }

  return SUCCESS;
}

_INLINE_ int
is_new(IN idx_t wlist[], IN const uint32_t ctr)
{
  for(uint32_t i = 0; i < ctr; i++)
  {
    if(wlist[i] == wlist[ctr])
    {
      return 0;
    }
  }

  return 1;
}

// Assumption 1) paddded_len % 64 = 0!
// Assumption 2) a is a len bits array. It is padded to be a padded_len
//               bytes array. The padded area may be modified and should
//               be ignored outside the function scope.
ret_t
generate_sparse_rep(OUT uint64_t *    a,
                    OUT idx_t         wlist[],
                    IN const uint32_t weight,
                    IN const uint32_t len,
                    IN const uint32_t padded_len,
                    IN OUT aes_ctr_prf_state_t *prf_state)
{
  assert(padded_len % 64 == 0);
  // Bits comparison
  assert((padded_len * 8) >= len);

  uint64_t ctr = 0;

  // Generate weight rand numbers
  do
  {
    GUARD(get_rand_mod_len(&wlist[ctr], len, prf_state));
    ctr += is_new(wlist, ctr);
  } while(ctr < weight);

  // Initialize to zero
  memset(a, 0, (len + 7) >> 3);

  // Assign values to "a"
  secure_set_bits(a, wlist, padded_len, weight);

  return SUCCESS;
}
