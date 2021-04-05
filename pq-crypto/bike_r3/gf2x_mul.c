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

_INLINE_ void karatzuba_add1(OUT uint64_t *alah,
                             OUT uint64_t *blbh,
                             IN const uint64_t *a,
                             IN const uint64_t *b,
                             IN const size_t    qwords_len)
{
  assert(qwords_len % REG_QWORDS == 0);

  REG_T va0, va1, vb0, vb1;

  for(size_t i = 0; i < qwords_len; i += REG_QWORDS) {
    va0 = LOAD(&a[i]);
    va1 = LOAD(&a[i + qwords_len]);
    vb0 = LOAD(&b[i]);
    vb1 = LOAD(&b[i + qwords_len]);

    STORE(&alah[i], va0 ^ va1);
    STORE(&blbh[i], vb0 ^ vb1);
  }
}

_INLINE_ void karatzuba_add2(OUT uint64_t *z,
                             IN const uint64_t *x,
                             IN const uint64_t *y,
                             IN const size_t    qwords_len)
{
  assert(qwords_len % REG_QWORDS == 0);

  REG_T vx, vy;

  for(size_t i = 0; i < qwords_len; i += REG_QWORDS) {
    vx = LOAD(&x[i]);
    vy = LOAD(&y[i]);

    STORE(&z[i], vx ^ vy);
  }
}

_INLINE_ void karatzuba_add3(OUT uint64_t *c,
                             IN const uint64_t *mid,
                             IN const size_t    qwords_len)
{
  assert(qwords_len % REG_QWORDS == 0);

  REG_T vr0, vr1, vr2, vr3, vt;

  uint64_t *c0 = c;
  uint64_t *c1 = &c[qwords_len];
  uint64_t *c2 = &c[2 * qwords_len];
  uint64_t *c3 = &c[3 * qwords_len];

  for(size_t i = 0; i < qwords_len; i += REG_QWORDS) {
    vr0 = LOAD(&c0[i]);
    vr1 = LOAD(&c1[i]);
    vr2 = LOAD(&c2[i]);
    vr3 = LOAD(&c3[i]);
    vt  = LOAD(&mid[i]);

    STORE(&c1[i], vt ^ vr0 ^ vr1);
    STORE(&c2[i], vt ^ vr2 ^ vr3);
  }
}

// c = a mod (x^r - 1)
_INLINE_ void gf2x_red(OUT pad_r_t *c, IN const dbl_pad_r_t *a)
{
  const uint64_t *a64 = (const uint64_t *)a;
  uint64_t *      c64 = (uint64_t *)c;

  for(size_t i = 0; i < R_QWORDS; i += REG_QWORDS) {
    REG_T vt0 = LOAD(&a64[i]);
    REG_T vt1 = LOAD(&a64[i + R_QWORDS]);
    REG_T vt2 = LOAD(&a64[i + R_QWORDS - 1]);

    vt1 = SLLI_I64(vt1, LAST_R_QWORD_TRAIL);
    vt2 = SRLI_I64(vt2, LAST_R_QWORD_LEAD);

    vt0 ^= (vt1 | vt2);

    STORE(&c64[i], vt0);
  }

  c64[R_QWORDS - 1] &= LAST_R_QWORD_MASK;

  // Clean the secrets from the upper part of c
  secure_clean((uint8_t *)&c64[R_QWORDS],
               (R_PADDED_QWORDS - R_QWORDS) * sizeof(uint64_t));
}

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
                        uint64_t *         sec_buf)
{
  if(qwords_len <= GF2X_BASE_QWORDS) {
    gf2x_mul_base(c, a, b);
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
  karatzuba(c0, a_lo, b_lo, half_qw_len, half_qw_len, sec_buf);

  // If the real number of digits n is less or equal to n_padded/2 then:
  //     a_hi = 0 and b_hi = 0
  // and
  //     (a_hi|a_lo)*(b_hi|b_lo) = a_lo*b_lo
  // so we can skip the remaining two multiplications
  if(qwords_len > half_qw_len) {
    // Compute a_hi*b_hi and store the result in (c3|c2)
    karatzuba(c2, a_hi, b_hi, qwords_len - half_qw_len, half_qw_len, sec_buf);

    // Compute alah = (a_lo + a_hi) and blbh = (b_lo + b_hi)
    karatzuba_add1(alah, blbh, a, b, half_qw_len);

    // Compute (c1 + c2) and store the result in tmp
    karatzuba_add2(tmp, c1, c2, half_qw_len);

    // Compute alah*blbh and store the result in (c2|c1)
    karatzuba(c1, alah, blbh, half_qw_len, half_qw_len, sec_buf);

    // Add (tmp|tmp) and (c3|c0) to (c2|c1)
    karatzuba_add3(c0, tmp, half_qw_len);
  }
}

void gf2x_mod_mul(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b)
{
  bike_static_assert((R_PADDED_BYTES % 2 == 0), karatzuba_n_is_odd);

  DEFER_CLEANUP(dbl_pad_r_t t = {0}, dbl_pad_r_cleanup);
  ALIGN(ALIGN_BYTES) uint64_t secure_buffer[SECURE_BUFFER_QWORDS];

  karatzuba((uint64_t *)&t, (const uint64_t *)a, (const uint64_t *)b, R_QWORDS,
            R_PADDED_QWORDS, secure_buffer);

  gf2x_red(c, &t);

  secure_clean((uint8_t *)secure_buffer, sizeof(secure_buffer));
}

void gf2x_mod_sqr_in_place(IN OUT pad_r_t *a, OUT dbl_pad_r_t *secure_buffer)
{
  gf2x_sqr(secure_buffer, a);
  gf2x_red(a, secure_buffer);
}
