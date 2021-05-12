/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * The rotate functions are based on the Barrel shifter described in [1] and
 * some code snippets from [2]:
 *
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

#if defined(S2N_BIKE_R3_AVX2)

#include "decode.h"
#include "decode_internal.h"
#include "utilities.h"

#define AVX2_INTERNAL
#include "x86_64_intrinsic.h"

#define R_YMM_HALF_LOG2 UPTOPOW2(R_YMM / 2)

_INLINE_ void
rotate256_big(OUT syndrome_t *out, IN const syndrome_t *in, IN size_t ymm_num)
{
  // For preventing overflows (comparison in bytes)
  bike_static_assert(sizeof(*out) >
                       (BYTES_IN_YMM * (R_YMM + (2 * R_YMM_HALF_LOG2))),
                     rotr_big_err);

  *out = *in;

  for(uint32_t idx = R_YMM_HALF_LOG2; idx >= 1; idx >>= 1) {
    const uint8_t mask       = secure_l32_mask(ymm_num, idx);
    const __m256i blend_mask = SET1_I8(mask);
    ymm_num                  = ymm_num - (idx & mask);

    for(size_t i = 0; i < (R_YMM + idx); i++) {
      __m256i a = LOAD(&out->qw[4 * (i + idx)]);
      __m256i b = LOAD(&out->qw[4 * i]);
      b         = BLENDV_I8(b, a, blend_mask);
      STORE(&out->qw[4 * i], b);
    }
  }
}

_INLINE_ void
rotate256_small(OUT syndrome_t *out, IN const syndrome_t *in, size_t count)
{
  __m256i        carry_in   = SET_ZERO;
  const int      count64    = (int)count & 0x3f;
  const uint64_t count_mask = (count >> 5) & 0xe;

  __m256i       idx       = SET_I32(7, 6, 5, 4, 3, 2, 1, 0);
  const __m256i zero_mask = SET_I64(-1, -1, -1, 0);
  const __m256i count_vet = SET1_I8(count_mask);

  ALIGN(ALIGN_BYTES)
  const uint8_t zero_mask2_buf[] = {
    0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x84, 0x84, 0x84,
    0x84, 0x84, 0x84, 0x84, 0x84, 0x82, 0x82, 0x82, 0x82, 0x82, 0x82,
    0x82, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80};
  __m256i zero_mask2 = LOAD(zero_mask2_buf);

  zero_mask2 = SUB_I8(zero_mask2, count_vet);
  idx        = ADD_I8(idx, count_vet);

  for(int i = R_YMM; i >= 0; i--) {
    // Load the next 256 bits
    __m256i in256 = LOAD(&in->qw[4 * i]);

    // Rotate the current and previous 256 registers so that their quadwords
    // would be in the right positions.
    __m256i carry_out = PERMVAR_I32(in256, idx);
    in256             = BLENDV_I8(carry_in, carry_out, zero_mask2);

    // Shift less than 64 (quadwords internal)
    __m256i inner_carry = BLENDV_I8(carry_in, in256, zero_mask);
    inner_carry         = PERM_I64(inner_carry, 0x39);
    const __m256i out256 =
      SRLI_I64(in256, count64) | SLLI_I64(inner_carry, (int)64 - count64);

    // Store the rotated value
    STORE(&out->qw[4 * i], out256);
    carry_in = carry_out;
  }
}

void rotate_right_avx2(OUT syndrome_t *out,
                       IN const syndrome_t *in,
                       IN const uint32_t    bitscount)
{
  // 1) Rotate in granularity of 256 bits blocks, using YMMs
  rotate256_big(out, in, (bitscount / BITS_IN_YMM));
  // 2) Rotate in smaller granularity (less than 256 bits), using YMMs
  rotate256_small(out, out, (bitscount % BITS_IN_YMM));
}

// Duplicates the first R_BITS of the syndrome three times
// |------------------------------------------|
// |  Third copy | Second copy | first R_BITS |
// |------------------------------------------|
// This is required by the rotate functions.
void dup_avx2(IN OUT syndrome_t *s)
{
  s->qw[R_QWORDS - 1] =
    (s->qw[0] << LAST_R_QWORD_LEAD) | (s->qw[R_QWORDS - 1] & LAST_R_QWORD_MASK);

  for(size_t i = 0; i < (2 * R_QWORDS) - 1; i++) {
    s->qw[R_QWORDS + i] =
      (s->qw[i] >> LAST_R_QWORD_TRAIL) | (s->qw[i + 1] << LAST_R_QWORD_LEAD);
  }
}

// Use half-adder as described in [1].
void bit_sliced_adder_avx2(OUT upc_t *upc,
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

void bit_slice_full_subtract_avx2(OUT upc_t *upc, IN uint8_t val)
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
