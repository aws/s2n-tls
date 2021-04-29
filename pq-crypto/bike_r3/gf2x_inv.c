/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * The inversion algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#include "cleanup.h"
#include "gf2x.h"
#include "gf2x_internal.h"

// c = a^2^2^num_sqrs
_INLINE_ void repeated_squaring(OUT pad_r_t *c,
                                IN pad_r_t *    a,
                                IN const size_t num_sqrs,
                                OUT dbl_pad_r_t *sec_buf)
{
  c->val = a->val;

  for(size_t i = 0; i < num_sqrs; i++) {
    gf2x_mod_sqr_in_place(c, sec_buf);
  }
}

// The gf2x_mod_inv function implements inversion in F_2[x]/(x^R - 1)
// based on [1](Algorithm 2).

// In every iteration, [1](Algorithm 2) performs two exponentiations:
// exponentiation 0 (exp0) and exponentiation 1 (exp1) of the form f^(2^k).
// These exponentiations are computed either by repeated squaring of f, k times,
// or by a single k-squaring of f. The method for a specific value of k
// is chosen based on the performance of squaring and k-squaring.
//
// Benchmarks on several platforms indicate that a good threshold
// for switching from repeated squaring to k-squaring is k = 64.
#define K_SQR_THR (64)

// k-squaring is computed by a permutation of bits of the input polynomial,
// as defined in [1](Observation 1). The required parameter for the permutation
// is l = (2^k)^-1 % R.
// Therefore, there are two sets of parameters for every exponentiation:
//   - exp0_k and exp1_k
//   - exp0_l and exp1_l

// Exponentiation 0 computes f^2^2^(i-1) for 0 < i < MAX_I.
// Exponentiation 1 computes f^2^((r-2) % 2^i) for 0 < i < MAX_I,
// only when the i-th bit of (r-2) is 1. Therefore, the value 0 in
// exp1_k[i] and exp1_l[i] means that exp1 is skipped in i-th iteration.

// To quickly generate all the required parameters in Sage:
//   r = DESIRED_R
//   max_i = floor(log(r-2, 2)) + 1
//   exp0_k = [2^i for i in range(max_i)]
//   exp0_l = [inverse_mod((2^k) % r, r) for k in exp0_k]
//   exp1_k = [(r-2)%(2^i) if ((r-2) & (1<<i)) else 0 for i in range(max_i)]
//   exp1_l = [inverse_mod((2^k) % r, r) if k != 0 else 0 for k in exp1_k]

#if(LEVEL == 1)
// The parameters below are hard-coded for R=12323
bike_static_assert((R_BITS == 12323), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define MAX_I (14)
#  define EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
#  define EXP0_L_VALS                                                           \
    6162, 3081, 3851, 5632, 22, 484, 119, 1838, 1742, 3106, 10650, 1608, 10157, \
      8816
#  define EXP1_K_VALS 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 33, 4129
#  define EXP1_L_VALS 0, 0, 0, 0, 0, 6162, 0, 0, 0, 0, 0, 0, 242, 5717

#else
// The parameters below are hard-coded for R=24659
bike_static_assert((R_BITS == 24659), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define MAX_I (15)
#  define EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
#  define EXP0_L_VALS                                                          \
    12330, 6165, 7706, 3564, 2711, 1139, 15053, 1258, 4388, 20524, 9538, 6393, \
      10486, 1715, 6804
#  define EXP1_K_VALS 0, 0, 0, 0, 1, 0, 17, 0, 0, 0, 0, 0, 0, 81, 8273
#  define EXP1_L_VALS 0, 0, 0, 0, 12330, 0, 13685, 0, 0, 0, 0, 0, 0, 23678, 19056

#endif

// Inversion in F_2[x]/(x^R - 1), [1](Algorithm 2).
// c = a^{-1} mod x^r-1
void gf2x_mod_inv(OUT pad_r_t *c, IN const pad_r_t *a)
{
  // Note that exp0/1_k/l are predefined constants that depend only on the value
  // of R. This value is public. Therefore, branches in this function, which
  // depends on R, are also "public". Code that releases these branches
  // (taken/not-taken) does not leak secret information.
  const size_t exp0_k[MAX_I] = {EXP0_K_VALS};
  const size_t exp0_l[MAX_I] = {EXP0_L_VALS};
  const size_t exp1_k[MAX_I] = {EXP1_K_VALS};
  const size_t exp1_l[MAX_I] = {EXP1_L_VALS};

  DEFER_CLEANUP(pad_r_t f = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t g = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t t = {0}, pad_r_cleanup);
  DEFER_CLEANUP(dbl_pad_r_t sec_buf = {0}, dbl_pad_r_cleanup);

  // Steps 2 and 3 in [1](Algorithm 2)
  f.val = a->val;
  t.val = a->val;

  for(size_t i = 1; i < MAX_I; i++) {
    // Step 5 in [1](Algorithm 2), exponentiation 0: g = f^2^2^(i-1)
    if(exp0_k[i - 1] <= K_SQR_THR) {
      repeated_squaring(&g, &f, exp0_k[i - 1], &sec_buf);
    } else {
      k_squaring(&g, &f, exp0_l[i - 1]);
    }

    // Step 6, [1](Algorithm 2): f = f*g
    gf2x_mod_mul(&f, &g, &f);

    if(exp1_k[i] != 0) {
      // Step 8, [1](Algorithm 2), exponentiation 1: g = f^2^((r-2) % 2^i)
      if(exp1_k[i] <= K_SQR_THR) {
        repeated_squaring(&g, &f, exp1_k[i], &sec_buf);
      } else {
        k_squaring(&g, &f, exp1_l[i]);
      }

      // Step 9, [1](Algorithm 2): t = t*g;
      gf2x_mod_mul(&t, &g, &t);
    }
  }

  // Step 10, [1](Algorithm 2): c = t^2
  gf2x_mod_sqr_in_place(&t, &sec_buf);
  c->val = t.val;
}
