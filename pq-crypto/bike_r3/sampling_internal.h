/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "pq-crypto/s2n_pq.h"
#include "defs.h"
#include "types.h"

void secure_set_bits_port(OUT pad_r_t *r,
                          IN size_t    first_pos,
                          IN const idx_t *wlist,
                          IN size_t       w_size);

// Compares wlist[ctr] to w[i] for all i < ctr.
// Returns 0 if wlist[ctr] is contained in wlist, returns 1 otherwise.
int is_new_port(IN const idx_t *wlist, IN const size_t ctr);

#if defined(S2N_BIKE_R3_AVX2)
void secure_set_bits_avx2(OUT pad_r_t *r,
                          IN size_t    first_pos,
                          IN const idx_t *wlist,
                          IN size_t       w_size);

int is_new_avx2(IN const idx_t *wlist, IN const size_t ctr);
#endif

#if defined(S2N_BIKE_R3_AVX512)
void secure_set_bits_avx512(OUT pad_r_t *r,
                            IN size_t    first_pos,
                            IN const idx_t *wlist,
                            IN size_t       w_size);
int is_new_avx512(IN const idx_t *wlist, IN const size_t ctr);
#endif

typedef struct sampling_ctx_st {
  void (*secure_set_bits)(OUT pad_r_t *r,
                          IN size_t    first_pos,
                          IN const idx_t *wlist,
                          IN size_t       w_size);
  int (*is_new)(IN const idx_t *wlist, IN const size_t ctr);
} sampling_ctx;

_INLINE_ void sampling_ctx_init(sampling_ctx *ctx)
{
#if defined(S2N_BIKE_R3_AVX512)
  if(s2n_bike_r3_is_avx512_enabled()) {
    ctx->secure_set_bits = secure_set_bits_avx512;
    ctx->is_new          = is_new_avx512;
  } else
#endif
#if defined(S2N_BIKE_R3_AVX2)
  if(s2n_bike_r3_is_avx2_enabled()) {
    ctx->secure_set_bits = secure_set_bits_avx2;
    ctx->is_new          = is_new_avx2;
  } else
#endif
  {
    ctx->secure_set_bits = secure_set_bits_port;
    ctx->is_new          = is_new_port;
  }
}
