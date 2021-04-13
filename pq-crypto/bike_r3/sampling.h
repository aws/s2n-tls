/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include <stdlib.h>
#include "aes_ctr_prf.h"
#include "pq-crypto/s2n_pq_random.h"
#include "utils/s2n_result.h"
#include "utilities.h"

typedef enum
{
  NO_RESTRICTION = 0,
  MUST_BE_ODD    = 1
} must_be_odd_t;

_INLINE_ ret_t get_seeds(OUT seeds_t *seeds) {
  if(s2n_result_is_ok(s2n_get_random_bytes(seeds->seed[0].raw, sizeof(seeds_t)))) {
    return SUCCESS;
  } else {
    BIKE_ERROR(E_FAIL_TO_GET_SEED);
  }
}

// Returns an array of r pseudorandom bits. If an odd
// weight of r is required, set must_be_odd to MUST_BE_ODD.
ret_t sample_uniform_r_bits(OUT r_t *r,
                            IN const seed_t *seed,
                            IN must_be_odd_t must_be_odd);

ret_t generate_sparse_rep(OUT pad_r_t *r,
                          OUT idx_t *wlist,
                          IN OUT aes_ctr_prf_state_t *prf_state);

ret_t generate_error_vector(OUT pad_e_t *e, IN const seed_t *seed);

// When "a" is considered as part of some larger array, then a_first_pos
// is the start position of "a" in the large array.
void secure_set_bits(OUT pad_r_t *r,
                     IN size_t    first_pos,
                     IN const idx_t *wlist,
                     IN size_t       w_size);
