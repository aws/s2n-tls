/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include <assert.h>

#include "cleanup.h"
#include "gf2x.h"
#include "gf2x_internal.h"

// The secure buffer size required for Karatsuba is computed by:
//    size(n) = 3*n/2 + size(n/2) = 3*sum_{i}{n/2^i} < 3n
#define SECURE_BUFFER_QWORDS (3 * R_PADDED_QWORDS)

// Karatsuba multiplication algorithm.
// Input arguments a and b are padded with zeros, here:
//   - n: real number of digits in a and b (R_QWORDS)
//   - n_padded: padded number of digits of a and b (assumed to be power of 2)
// A buffer sec_buf is used for storing temporary data between recursion calls.
// It might contain secrets, and therefore should be securely cleaned after
// completion.
_INLINE_ void karatzuba(OUT uint64_t *c,
                        IN const uint64_t *a,
                        IN const uint64_t *b,
                        IN const size_t    qwords_len,
                        IN const size_t    qwords_len_pad,
                        uint64_t *         sec_buf,
                        IN const gf2x_ctx *ctx)
{
  if(qwords_len <= ctx->mul_base_qwords) {
    ctx->mul_base(c, a, b);
    return;
  }

  const size_t half_qw_len = qwords_len_pad >> 1;

  // Split a and b into low and high parts of size n_padded/2
  const uint64_t *a_lo = a;
  const uint64_t *b_lo = b;
  const uint64_t *a_hi = &a[half_qw_len];
  const uint64_t *b_hi = &b[half_qw_len];

  // Split c into 4 parts of size n_padded/2 (the last ptr is not needed)
  uint64_t *c0 = c;
  uint64_t *c1 = &c[half_qw_len];
  uint64_t *c2 = &c[half_qw_len * 2];

  // Allocate 3 ptrs of size n_padded/2  on sec_buf
  uint64_t *alah = sec_buf;
  uint64_t *blbh = &sec_buf[half_qw_len];
  uint64_t *tmp  = &sec_buf[half_qw_len * 2];

  // Move sec_buf ptr to the first free location for the next recursion call
  sec_buf = &sec_buf[half_qw_len * 3];

  // Compute a_lo*b_lo and store the result in (c1|c0)
  karatzuba(c0, a_lo, b_lo, half_qw_len, half_qw_len, sec_buf, ctx);

  // If the real number of digits n is less or equal to n_padded/2 then:
  //     a_hi = 0 and b_hi = 0
  // and
  //     (a_hi|a_lo)*(b_hi|b_lo) = a_lo*b_lo
  // so we can skip the remaining two multiplications
  if(qwords_len > half_qw_len) {
    // Compute a_hi*b_hi and store the result in (c3|c2)
    karatzuba(c2, a_hi, b_hi, qwords_len - half_qw_len, half_qw_len, sec_buf,
              ctx);

    // Compute alah = (a_lo + a_hi) and blbh = (b_lo + b_hi)
    ctx->karatzuba_add1(alah, blbh, a, b, half_qw_len);

    // Compute (c1 + c2) and store the result in tmp
    ctx->karatzuba_add2(tmp, c1, c2, half_qw_len);

    // Compute alah*blbh and store the result in (c2|c1)
    karatzuba(c1, alah, blbh, half_qw_len, half_qw_len, sec_buf, ctx);

    // Add (tmp|tmp) and (c3|c0) to (c2|c1)
    ctx->karatzuba_add3(c0, tmp, half_qw_len);
  }
}

void gf2x_mod_mul_with_ctx(OUT pad_r_t *c,
                           IN const pad_r_t *a,
                           IN const pad_r_t *b,
                           IN const gf2x_ctx *ctx)
{
  bike_static_assert((R_PADDED_BYTES % 2 == 0), karatzuba_n_is_odd);

  DEFER_CLEANUP(dbl_pad_r_t t = {0}, dbl_pad_r_cleanup);
  ALIGN(ALIGN_BYTES) uint64_t secure_buffer[SECURE_BUFFER_QWORDS];

  karatzuba((uint64_t *)&t, (const uint64_t *)a, (const uint64_t *)b, R_QWORDS,
            R_PADDED_QWORDS, secure_buffer, ctx);

  ctx->red(c, &t);

  secure_clean((uint8_t *)secure_buffer, sizeof(secure_buffer));
}

void gf2x_mod_mul(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b)
{
  bike_static_assert((R_PADDED_BYTES % 2 == 0), karatzuba_n_is_odd);

  // Initialize gf2x methods struct
  gf2x_ctx ctx = {0};
  gf2x_ctx_init(&ctx);

  gf2x_mod_mul_with_ctx(c, a, b, &ctx);
}
