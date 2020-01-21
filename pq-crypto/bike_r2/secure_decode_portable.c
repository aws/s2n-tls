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

#include "decode.h"
#include "utilities.h"

#define R_QW_HALF_LOG2 UPTOPOW2(R_QW / 2)

_INLINE_ void
rotr_big(OUT syndrome_t *out, IN const syndrome_t *in, IN size_t qw_num)
{
  // For preventing overflows (comparison in bytes)
  bike_static_assert(sizeof(*out) > 8 * (R_QW + (2 * R_QW_HALF_LOG2)),
                     rotr_big_err);

  memcpy(out, in, sizeof(*in));

  for(uint32_t idx = R_QW_HALF_LOG2; idx >= 1; idx >>= 1)
  {
    // Convert 32 bit mask to 64 bit mask
    const uint64_t mask = ((uint32_t)secure_l32_mask(qw_num, idx) + 1U) - 1ULL;
    qw_num              = qw_num - (idx & mask);

    // Rotate R_QW quadwords and another idx quadwords needed by the next
    // iteration
    for(size_t i = 0; i < (R_QW + idx); i++)
    {
      out->qw[i] = (out->qw[i] & (~mask)) | (out->qw[i + idx] & mask);
    }
  }
}

_INLINE_ void
rotr_small(OUT syndrome_t *out, IN const syndrome_t *in, IN const size_t bits)
{
  bike_static_assert(bits < 64, rotr_small_err);
  bike_static_assert(sizeof(*out) > (8 * R_QW), rotr_small_qw_err);

  for(size_t i = 0; i < R_QW; i++)
  {
    out->qw[i] = (in->qw[i] >> bits) | (in->qw[i + 1] << (64 - bits));
  }
}

void
rotate_right(OUT syndrome_t *out,
             IN const syndrome_t *in,
             IN const uint32_t    bitcount)
{
  // Rotate (64-bit) quad-words
  rotr_big(out, in, (bitcount / 64));
  // Rotate bits (less than 64)
  rotr_small(out, out, (bitcount % 64));
}
