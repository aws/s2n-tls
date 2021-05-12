/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#if defined(S2N_BIKE_R3_AVX2)

#include <assert.h>

#include "sampling_internal.h"

#define AVX2_INTERNAL
#include "x86_64_intrinsic.h"

// For improved performance, we process NUM_YMMS amount of data in parallel.
#define NUM_YMMS    (4)
#define YMMS_QWORDS (QWORDS_IN_YMM * NUM_YMMS)

void secure_set_bits_avx2(OUT pad_r_t *   r,
                          IN const size_t first_pos,
                          IN const idx_t *wlist,
                          IN const size_t w_size)
{
  // The function assumes that the size of r is a multiple
  // of the cumulative size of used YMM registers.
  assert((sizeof(*r) / sizeof(uint64_t)) % YMMS_QWORDS == 0);

  // va vectors hold the bits of the output array "r"
  // va_pos_qw vectors hold the qw position indices of "r"
  // The algorithm works as follows:
  //   1. Initialize va_pos_qw with starting positions of qw's of "r"
  //      va_pos_qw = (3, 2, 1, 0);
  //   2. While the size of "r" is not exceeded:
  //   3.   For each w in wlist:
  //   4.     Compare the pos_qw of w with positions in va_pos_qw
  //          and for the position which is equal set the appropriate
  //          bit in va vector.
  //   5.   Set va_pos_qw to the next qw positions of "r"
  __m256i va[NUM_YMMS], va_pos_qw[NUM_YMMS], va_mask;
  __m256i w_pos_qw, w_pos_bit;
  __m256i one, inc;

  uint64_t *r64 = (uint64_t *)r;

  one = SET1_I64(1);
  inc = SET1_I64(QWORDS_IN_YMM);

  // 1. Initialize
  va_pos_qw[0] = SET_I64(3, 2, 1, 0);
  for(size_t i = 1; i < NUM_YMMS; i++) {
    va_pos_qw[i] = ADD_I64(va_pos_qw[i - 1], inc);
  }

  // va_pos_qw vectors hold qw positions 0 .. (NUM_YMMS * QWORDS_IN_YMM - 1)
  // Therefore, we set the increment vector inc such that by adding it to
  // va_pos_qw vectors, they hold the next YMM_QWORDS qw positions.
  inc = SET1_I64(YMMS_QWORDS);

  for(size_t i = 0; i < (sizeof(*r) / sizeof(uint64_t)); i += YMMS_QWORDS) {
    for(size_t va_iter = 0; va_iter < NUM_YMMS; va_iter++) {
      va[va_iter] = SET_ZERO;
    }

    for(size_t w_iter = 0; w_iter < w_size; w_iter++) {
      int32_t w = wlist[w_iter] - first_pos;
      w_pos_qw  = SET1_I64(w >> 6);
      w_pos_bit = SLLI_I64(one, w & MASK(6));

      // 4. Compare the positions in va_pos_qw with w_pos_qw
      //    and set the appropriate bit in va
      for(size_t va_iter = 0; va_iter < NUM_YMMS; va_iter++) {
        va_mask = CMPEQ_I64(va_pos_qw[va_iter], w_pos_qw);
        va[va_iter] |= (va_mask & w_pos_bit);
      }
    }

    // 5. Set the va_pos_qw to the next qw positions of r
    //    and store the previously computed data in r
    for(size_t va_iter = 0; va_iter < NUM_YMMS; va_iter++) {
      STORE(&r64[i + (va_iter * QWORDS_IN_YMM)], va[va_iter]);
      va_pos_qw[va_iter] = ADD_I64(va_pos_qw[va_iter], inc);
    }
  }
}

int is_new_avx2(IN const idx_t *wlist, IN const size_t ctr)
{
  bike_static_assert((sizeof(idx_t) == sizeof(uint32_t)), idx_t_is_not_uint32_t);

  REG_T idx_ctr = SET1_I32(wlist[ctr]);

  for(size_t i = 0; i < ctr; i += REG_DWORDS) {
    // Comparisons are done with SIMD instructions with each SIMD register
    // containing REG_DWORDS elements. We compare registers element-wise:
    // idx_ctr = {8 repetitions of wlist[ctr]}, with
    // idx_cur = {8 consecutive elements from wlist}.
    // In the last iteration we consider wlist elements only up to ctr.

    REG_T    idx_cur = LOAD(&wlist[i]);
    REG_T    cmp_res = CMPEQ_I32(idx_ctr, idx_cur);
    uint32_t check   = MOVEMASK(cmp_res);

    // Handle the last iteration by appropriate masking.
    if(ctr < (i + REG_DWORDS)) {
      // MOVEMASK instruction in AVX2 compares corresponding bytes from
      // two given vector registers and produces a 32-bit mask. On the other hand,
      // we compare idx_t elements, not bytes, so we multiply by sizeof(idx_t).
      check &= MASK((ctr - i) * sizeof(idx_t));
    }

    if(check != 0) {
      return 0;
    }
  }

  return 1;
}

#endif

typedef int dummy_typedef_to_avoid_empty_translation_unit_warning;
