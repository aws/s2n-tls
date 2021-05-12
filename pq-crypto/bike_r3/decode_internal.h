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

// Rotate right the first R_BITS of a syndrome.
// At input, the syndrome is stored as three R_BITS triplicate.
// (this makes rotation easier to implement)
// For the output: the output syndrome has only one R_BITS rotation, the remaining
// (2 * R_BITS) bits are undefined.
void rotate_right_port(OUT syndrome_t *out,
                       IN const syndrome_t *in,
                       IN uint32_t          bitscount);
void dup_port(IN OUT syndrome_t *s);
void bit_sliced_adder_port(OUT upc_t *upc,
                           IN OUT syndrome_t *rotated_syndrome,
                           IN const size_t    num_of_slices);
void bit_slice_full_subtract_port(OUT upc_t *upc, IN uint8_t val);

#if defined(S2N_BIKE_R3_AVX2)
void rotate_right_avx2(OUT syndrome_t *out,
                       IN const syndrome_t *in,
                       IN uint32_t          bitscount);
void dup_avx2(IN OUT syndrome_t *s);
void bit_sliced_adder_avx2(OUT upc_t *upc,
                           IN OUT syndrome_t *rotated_syndrome,
                           IN const size_t    num_of_slices);
void bit_slice_full_subtract_avx2(OUT upc_t *upc, IN uint8_t val);
#endif

#if defined(S2N_BIKE_R3_AVX512)
void rotate_right_avx512(OUT syndrome_t *out,
                         IN const syndrome_t *in,
                         IN uint32_t          bitscount);
void dup_avx512(IN OUT syndrome_t *s);
void bit_sliced_adder_avx512(OUT upc_t *upc,
                             IN OUT syndrome_t *rotated_syndrome,
                             IN const size_t    num_of_slices);
void bit_slice_full_subtract_avx512(OUT upc_t *upc, IN uint8_t val);
#endif

// Decode methods struct
typedef struct decode_ctx_st {
  void (*rotate_right)(OUT syndrome_t *out,
                       IN const syndrome_t *in,
                       IN uint32_t          bitscount);
  void (*dup)(IN OUT syndrome_t *s);
  void (*bit_sliced_adder)(OUT upc_t *upc,
                           IN OUT syndrome_t *rotated_syndrom,
                           IN const size_t    num_of_slices);
  void (*bit_slice_full_subtract)(OUT upc_t *upc, IN uint8_t val);
} decode_ctx;

_INLINE_ void decode_ctx_init(decode_ctx *ctx)
{
#if defined(S2N_BIKE_R3_AVX512)
  if(s2n_bike_r3_is_avx512_enabled()) {
    ctx->rotate_right            = rotate_right_avx512;
    ctx->dup                     = dup_avx512;
    ctx->bit_sliced_adder        = bit_sliced_adder_avx512;
    ctx->bit_slice_full_subtract = bit_slice_full_subtract_avx512;
  } else
#endif
#if defined(S2N_BIKE_R3_AVX2)
  if(s2n_bike_r3_is_avx2_enabled()) {
    ctx->rotate_right            = rotate_right_avx2;
    ctx->dup                     = dup_avx2;
    ctx->bit_sliced_adder        = bit_sliced_adder_avx2;
    ctx->bit_slice_full_subtract = bit_slice_full_subtract_avx2;
  } else
#endif
  {
    ctx->rotate_right            = rotate_right_port;
    ctx->dup                     = dup_port;
    ctx->bit_sliced_adder        = bit_sliced_adder_port;
    ctx->bit_slice_full_subtract = bit_slice_full_subtract_port;
  }
}
