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

#include "gf2x.h"
#include "utilities.h"

#if !defined(USE_OPENSSL_GF2M)

// The algorithm is based on the windowing method, for example as in:
// Brent, R. P., Gaudry, P., Thomé, E., & Zimmermann, P. (2008, May), "Faster
// multiplication in GF (2)[x]". In: International Algorithmic Number Theory
// Symposium (pp. 153-166). Springer, Berlin, Heidelberg. In this implementation,
// the last three bits are multiplied using a schoolbook multiplicaiton.
void
gf2x_mul_1x1(uint64_t *c, uint64_t a, uint64_t b)
{
  uint64_t       h = 0, l = 0, g1, g2, u[8];
  const uint64_t w = 64;
  const uint64_t s = 3;
  // Multiplying 64 bits by 7 can results in an overflow of 3 bits.
  // Therefore, these bits are masked out, and are treated in step 3.
  const uint64_t b0 = b & 0x1fffffffffffffff;

  // Step 1: Calculate a multiplication table with 8 entries.
  u[0] = 0;
  u[1] = b0;
  u[2] = u[1] << 1;
  u[3] = u[2] ^ b0;
  u[4] = u[2] << 1;
  u[5] = u[4] ^ b0;
  u[6] = u[3] << 1;
  u[7] = u[6] ^ b0;

  // Step 2: Multiply two elements in parallel in poisitions i,i+s
  l = u[a & 7] ^ (u[(a >> 3) & 7] << 3);
  h = (u[(a >> 3) & 7] >> 61);
  for(uint32_t i = (2 * s); i < w; i += (2 * s))
  {
    g1 = u[(a >> i) & 7];
    g2 = u[(a >> (i + s)) & 7];

    l ^= (g1 << i) ^ (g2 << (i + s));
    h ^= (g1 >> (w - i)) ^ (g2 >> (w - (i + s)));
  }

  // Step 3: Multiply the last three bits.
  for(uint8_t i = 61; i < 64; i++)
  {
    uint64_t mask = (-((b >> i) & 1));
    l ^= ((a << i) & mask);
    h ^= ((a >> (w - i)) & mask);
  }

  c[0] = l;
  c[1] = h;
}

void
karatzuba_add1(OUT uint64_t *res,
               IN const uint64_t *a,
               IN const uint64_t *b,
               IN const uint64_t  n_half,
               IN uint64_t *alah)
{
  for(uint32_t j = 0; j < n_half; j++)
  {
    alah[j + 0 * n_half] = a[j] ^ a[n_half + j];
    alah[j + 1 * n_half] = b[j] ^ b[n_half + j];
    alah[j + 2 * n_half] = res[n_half + j] ^ res[2 * n_half + j];
  }
}

void
karatzuba_add2(OUT uint64_t *res1,
               OUT uint64_t *res2,
               IN const uint64_t *res,
               IN const uint64_t *tmp,
               IN const uint64_t  n_half)
{
  for(uint32_t j = 0; j < n_half; j++)
  {
    res1[j] ^= res[j] ^ tmp[j];
    res2[j] ^= res2[n_half + j] ^ tmp[j];
  }
}

void
red(uint64_t *a)
{
  for(uint32_t i = 0; i < R_QW; i++)
  {
    const uint64_t temp0 = a[R_QW + i - 1];
    const uint64_t temp1 = a[R_QW + i];
    a[i] ^= (temp0 >> LAST_R_QW_LEAD) | (temp1 << LAST_R_QW_TRAIL);
  }

  a[R_QW - 1] &= LAST_R_QW_MASK;

  // Clean the secrets from the upper half of a.
  secure_clean((uint8_t *)&a[R_QW], sizeof(uint64_t) * R_QW);
}

#endif
