/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "gf2x_internal.h"
#include "utilities.h"

#define LSB3(x) ((x)&7)

// 64x64 bit multiplication
// The algorithm is based on the windowing method, for example as in:
// Brent, R. P., Gaudry, P., Thomé, E., & Zimmermann, P. (2008, May), "Faster
// multiplication in GF (2)[x]". In: International Algorithmic Number Theory
// Symposium (pp. 153-166). Springer, Berlin, Heidelberg. In this implementation,
// the last three bits are multiplied using a schoolbook multiplication.
void gf2x_mul_base(OUT uint64_t *c, IN const uint64_t *a, IN const uint64_t *b)
{
  uint64_t       h = 0, l = 0, g1, g2, u[8];
  const uint64_t w  = 64;
  const uint64_t s  = 3;
  const uint64_t a0 = LOAD(a);
  const uint64_t b0 = LOAD(b);

  // Multiplying 64 bits by 7 can results in an overflow of 3 bits.
  // Therefore, these bits are masked out, and are treated in step 3.
  const uint64_t b0m = b0 & MASK(61);

  // Step 1: Calculate a multiplication table with 8 entries.
  u[0] = 0;
  u[1] = b0m;
  u[2] = u[1] << 1;
  u[3] = u[2] ^ b0m;
  u[4] = u[2] << 1;
  u[5] = u[4] ^ b0m;
  u[6] = u[3] << 1;
  u[7] = u[6] ^ b0m;

  // Step 2: Multiply two elements in parallel in positions i, i+s
  l = u[LSB3(a0)] ^ (u[LSB3(a0 >> 3)] << 3);
  h = (u[LSB3(a0 >> 3)] >> 61);

  for(size_t i = (2 * s); i < w; i += (2 * s)) {
    const size_t i2 = (i + s);

    g1 = u[LSB3(a0 >> i)];
    g2 = u[LSB3(a0 >> i2)];

    l ^= (g1 << i) ^ (g2 << i2);
    h ^= (g1 >> (w - i)) ^ (g2 >> (w - i2));
  }

  // Step 3: Multiply the last three bits.
  for(size_t i = 61; i < 64; i++) {
    uint64_t mask = (-((b0 >> i) & 1));
    l ^= ((a0 << i) & mask);
    h ^= ((a0 >> (w - i)) & mask);
  }

  STORE(&c[0], l);
  STORE(&c[1], h);
}

// c = a^2
void gf2x_sqr(OUT dbl_pad_r_t *c, IN const pad_r_t *a)
{
  const uint64_t *a64 = (const uint64_t *)a;
  uint64_t *      c64 = (uint64_t *)c;

  for(size_t i = 0; i < R_QWORDS; i++) {
    gf2x_mul_base(&c64[2 * i], &a64[i], &a64[i]);
  }
}
