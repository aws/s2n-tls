/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "decode.h"
#include "utilities.h"

#define R_QWORDS_HALF_LOG2 UPTOPOW2(R_QWORDS / 2)

_INLINE_ void
rotr_big(OUT syndrome_t *out, IN const syndrome_t *in, IN size_t qw_num)
{
  // For preventing overflows (comparison in bytes)
  bike_static_assert(sizeof(*out) > 8 * (R_QWORDS + (2 * R_QWORDS_HALF_LOG2)),
                     rotr_big_err);

  *out = *in;

  for(uint32_t idx = R_QWORDS_HALF_LOG2; idx >= 1; idx >>= 1) {
    // Convert 32 bit mask to 64 bit mask
    const uint64_t mask = ((uint32_t)secure_l32_mask(qw_num, idx) + 1U) - 1ULL;
    qw_num              = qw_num - (idx & u64_barrier(mask));

    // Rotate R_QWORDS quadwords and another idx quadwords,
    // as needed by the next iteration.
    for(size_t i = 0; i < (R_QWORDS + idx); i++) {
      out->qw[i] = (out->qw[i] & u64_barrier(~mask)) |
                   (out->qw[i + idx] & u64_barrier(mask));
    }
  }
}

_INLINE_ void
rotr_small(OUT syndrome_t *out, IN const syndrome_t *in, IN const size_t bits)
{
  bike_static_assert(bits < 64, rotr_small_err);
  bike_static_assert(sizeof(*out) > (8 * R_QWORDS), rotr_small_qw_err);

  // Convert |bits| to 0/1 by using !!bits; then create a mask of 0 or
  // 0xffffffffff Use high_shift to avoid undefined behaviour when doing x << 64;
  const uint64_t mask       = (0 - (!!bits));
  const uint64_t high_shift = (64 - bits) & u64_barrier(mask);

  for(size_t i = 0; i < R_QWORDS; i++) {
    const uint64_t low_part  = in->qw[i] >> bits;
    const uint64_t high_part = (in->qw[i + 1] << high_shift) & u64_barrier(mask);
    out->qw[i]               = low_part | high_part;
  }
}

void rotate_right(OUT syndrome_t *out,
                  IN const syndrome_t *in,
                  IN const uint32_t    bitscount)
{
  // Rotate (64-bit) quad-words
  rotr_big(out, in, (bitscount / 64));
  // Rotate bits (less than 64)
  rotr_small(out, out, (bitscount % 64));
}
