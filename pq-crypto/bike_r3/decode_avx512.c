/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * The rotation functions are based on the Barrel shifter described in [1]
 * and some modifed snippet from [2]
 * [1] Chou, T.: QcBits: Constant-Time Small-Key Code-Based Cryptography.
 *     In: Gier-lichs, B., Poschmann, A.Y. (eds.) Cryptographic Hardware
 *     and Embedded Systems– CHES 2016. pp. 280–300. Springer Berlin Heidelberg,
 *     Berlin, Heidelberg (2016)
 *
 * [2] Guimarães, Antonio, Diego F Aranha, and Edson Borin. 2019.
 *     “Optimized Implementation of QC-MDPC Code-Based Cryptography.”
 *     Concurrency and Computation: Practice and Experience 31 (18):
 *     e5089. https://doi.org/10.1002/cpe.5089.
 */

#if defined(S2N_BIKE_R3_AVX512)

#include "decode.h"
#include "decode_internal.h"
#include "utilities.h"

#define AVX512_INTERNAL
#include "x86_64_intrinsic.h"

#define R_ZMM_HALF_LOG2 UPTOPOW2(R_ZMM / 2)

_INLINE_ void
rotate512_big(OUT syndrome_t *out, IN const syndrome_t *in, size_t zmm_num)
{
  // For preventing overflows (comparison in bytes)
  bike_static_assert(sizeof(*out) >
                       (BYTES_IN_ZMM * (R_ZMM + (2 * R_ZMM_HALF_LOG2))),
                     rotr_big_err);
  *out = *in;

  for(uint32_t idx = R_ZMM_HALF_LOG2; idx >= 1; idx >>= 1) {
    const uint8_t mask = secure_l32_mask(zmm_num, idx);
    zmm_num            = zmm_num - (idx & mask);

    for(size_t i = 0; i < (R_ZMM + idx); i++) {
      const __m512i a = LOAD(&out->qw[8 * (i + idx)]);
      MSTORE(&out->qw[8 * i], mask, a);
    }
  }
}

// The rotate512_small function is a derivative of the code described in [1]
_INLINE_ void
rotate512_small(OUT syndrome_t *out, IN const syndrome_t *in, size_t bitscount)
{
  __m512i       previous     = SET_ZERO;
  const int     count64      = (int)bitscount & 0x3f;
  const __m512i count64_512  = SET1_I64(count64);
  const __m512i count64_512r = SET1_I64((int)64 - count64);

  const __m512i num_full_qw = SET1_I64(bitscount >> 6);
  const __m512i one         = SET1_I64(1);
  __m512i       a0, a1;

  __m512i idx = SET_I64(7, 6, 5, 4, 3, 2, 1, 0);

  // Positions above 7 are taken from the second register in
  // _mm512_permutex2var_epi64
  idx          = ADD_I64(idx, num_full_qw);
  __m512i idx1 = ADD_I64(idx, one);

  for(int i = R_ZMM; i >= 0; i--) {
    // Load the next 512 bits
    const __m512i in512 = LOAD(&in->qw[8 * i]);

    // Rotate the current and previous 512 registers so that their quadwords
    // would be in the right positions.
    a0 = PERMX2VAR_I64(in512, idx, previous);
    a1 = PERMX2VAR_I64(in512, idx1, previous);

    a0 = SRLV_I64(a0, count64_512);
    a1 = SLLV_I64(a1, count64_512r);

    // Shift less than 64 (quadwords internal)
    const __m512i out512 = a0 | a1;

    // Store the rotated value
    STORE(&out->qw[8 * i], out512);
    previous = in512;
  }
}

void rotate_right_avx512(OUT syndrome_t *out,
                         IN const syndrome_t *in,
                         IN const uint32_t    bitscount)
{
  // 1) Rotate in granularity of 512 bits blocks, using ZMMs
  rotate512_big(out, in, (bitscount / BITS_IN_ZMM));
  // 2) Rotate in smaller granularity (less than 512 bits), using ZMMs
  rotate512_small(out, out, (bitscount % BITS_IN_ZMM));
}

// Duplicates the first R_BITS of the syndrome three times
// |------------------------------------------|
// |  Third copy | Second copy | first R_BITS |
// |------------------------------------------|
// This is required by the rotate functions.
void dup_avx512(IN OUT syndrome_t *s)
{
  s->qw[R_QWORDS - 1] =
    (s->qw[0] << LAST_R_QWORD_LEAD) | (s->qw[R_QWORDS - 1] & LAST_R_QWORD_MASK);

  for(size_t i = 0; i < (2 * R_QWORDS) - 1; i++) {
    s->qw[R_QWORDS + i] =
      (s->qw[i] >> LAST_R_QWORD_TRAIL) | (s->qw[i + 1] << LAST_R_QWORD_LEAD);
  }
}

// Use half-adder as described in [1].
void bit_sliced_adder_avx512(OUT upc_t *upc,
                             IN OUT syndrome_t *rotated_syndrome,
                             IN const size_t    num_of_slices)
{
  // From cache-memory perspective this loop should be the outside loop
  for(size_t j = 0; j < num_of_slices; j++) {
    for(size_t i = 0; i < R_QWORDS; i++) {
      const uint64_t carry = (upc->slice[j].u.qw[i] & rotated_syndrome->qw[i]);
      upc->slice[j].u.qw[i] ^= rotated_syndrome->qw[i];
      rotated_syndrome->qw[i] = carry;
    }
  }
}

void bit_slice_full_subtract_avx512(OUT upc_t *upc, IN uint8_t val)
{
  // Borrow
  uint64_t br[R_QWORDS] = {0};

  for(size_t j = 0; j < SLICES; j++) {

    const uint64_t lsb_mask = 0 - (val & 0x1);
    val >>= 1;

    // Perform a - b with c as the input/output carry
    // br = 0 0 0 0 1 1 1 1
    // a  = 0 0 1 1 0 0 1 1
    // b  = 0 1 0 1 0 1 0 1
    // -------------------
    // o  = 0 1 1 0 0 1 1 1
    // c  = 0 1 0 0 1 1 0 1
    //
    // o  = a^b^c
    //            _     __    _ _   _ _     _
    // br = abc + abc + abc + abc = abc + ((a+b))c

    for(size_t i = 0; i < R_QWORDS; i++) {
      const uint64_t a      = upc->slice[j].u.qw[i];
      const uint64_t b      = lsb_mask;
      const uint64_t tmp    = ((~a) & b & (~br[i])) | ((((~a) | b) & br[i]));
      upc->slice[j].u.qw[i] = a ^ b ^ br[i];
      br[i]                 = tmp;
    }
  }
}

#endif

typedef int dummy_typedef_to_avoid_empty_translation_unit_warning;
