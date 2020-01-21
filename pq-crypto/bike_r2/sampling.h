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

#pragma once

#include "aes_ctr_prf.h"
#include "pq-crypto/pq_random.h"
#include "utilities.h"

typedef enum
{
  NO_RESTRICTION = 0,
  MUST_BE_ODD    = 1
} must_be_odd_t;

_INLINE_ ret_t
get_seeds(OUT seeds_t *seeds)
{
  // pq-random uses 0 for success and negative values for failure
  if(get_random_bytes(seeds->seed[0].raw, sizeof(seeds_t)) == 0)
  {
    return SUCCESS;
  }
  else
  {
    BIKE_ERROR(E_FAIL_TO_GET_SEED);
  }
}

// Return's an array of r pseudorandom bits
// No restrictions exist for the top or bottom bits -
// in case an odd number is requried then set must_be_odd=1
// Uses the provided prf context
ret_t
sample_uniform_r_bits_with_fixed_prf_context(OUT r_t *r,
                                             IN OUT
                                                 aes_ctr_prf_state_t *prf_state,
                                             IN const must_be_odd_t must_be_odd);

// Return's an array of r pseudorandom bits
// No restrictions exist for the top or bottom bits -
// in case an odd number is  requried then set must_be_odd=1
_INLINE_ ret_t
sample_uniform_r_bits(OUT r_t *r,
                      IN const seed_t *      seed,
                      IN const must_be_odd_t must_be_odd)
{
  // For the seedexpander
  DEFER_CLEANUP(aes_ctr_prf_state_t prf_state = {0}, aes_ctr_prf_state_cleanup);

  GUARD(init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, seed));

  GUARD(sample_uniform_r_bits_with_fixed_prf_context(r, &prf_state, must_be_odd));

  finalize_aes_ctr_prf(&prf_state);

  return SUCCESS;
}

// Generate a pseudorandom r of length len with a set weight
// Using the pseudorandom ctx supplied
// Outputs also a compressed (not ordered) list of indices
ret_t
generate_sparse_rep(OUT uint64_t *    a,
                    OUT idx_t         wlist[],
                    IN const uint32_t weight,
                    IN const uint32_t len,
                    IN const uint32_t padded_len,
                    IN OUT aes_ctr_prf_state_t *prf_state);

EXTERNC void
secure_set_bits(IN OUT uint64_t * a,
                IN const idx_t    wlist[],
                IN const uint32_t a_len,
                IN const uint32_t weight);
