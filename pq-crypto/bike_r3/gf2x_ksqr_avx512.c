/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * The k-squaring algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#if defined(S2N_BIKE_R3_AVX512)

#include "cleanup.h"
#include "gf2x_internal.h"

#define AVX512_INTERNAL
#include "x86_64_intrinsic.h"

#define NUM_ZMMS    (2)
#define NUM_OF_VALS (NUM_ZMMS * WORDS_IN_ZMM)

// clang-3.9 doesn't recognize these two macros
#if !defined(_MM_CMPINT_EQ)
#  define _MM_CMPINT_EQ (0)
#endif

#if !defined(_MM_CMPINT_NLT)
#  define _MM_CMPINT_NLT (5)
#endif

_INLINE_ void generate_map(OUT uint16_t *map, IN const size_t l_param)
{
  __m512i   vmap[NUM_ZMMS], vr, inc;
  __mmask32 mask[NUM_ZMMS];

  // The permutation map is generated in the following way:
  //   1. for i = 0 to map size:
  //   2.  map[i] = (i * l_param) % r
  // However, to avoid the expensive multiplication and modulo operations
  // we modify the algorithm to:
  //   1. map[0] = l_param
  //   2. for i = 1 to map size:
  //   3.   map[i] = map[i - 1] + l_param
  //   4.   if map[i] >= r:
  //   5.     map[i] = map[i] - r
  // This algorithm is parallelized with vector instructions by processing
  // certain number of values (NUM_OF_VALS) in parallel. Therefore,
  // in the beginning we need to initialize the first NUM_OF_VALS elements.
  for(size_t i = 0; i < NUM_OF_VALS; i++) {
    map[i] = (i * l_param) % R_BITS;
  }

  // Set the increment vector such that by adding it to vmap vectors
  // we will obtain the next NUM_OF_VALS elements of the map.
  inc = SET1_I16((l_param * NUM_OF_VALS) % R_BITS);
  vr  = SET1_I16(R_BITS);

  // Load the first NUM_OF_VALS elements in the vmap vectors
  for(size_t i = 0; i < NUM_ZMMS; i++) {
    vmap[i] = LOAD(&map[i * WORDS_IN_ZMM]);
  }

  for(size_t i = NUM_ZMMS; i < (R_PADDED / WORDS_IN_ZMM); i += NUM_ZMMS) {
    for(size_t j = 0; j < NUM_ZMMS; j++) {
      vmap[j] = ADD_I16(vmap[j], inc);
      mask[j] = CMPM_U16(vmap[j], vr, _MM_CMPINT_NLT);
      vmap[j] = MSUB_I16(vmap[j], mask[j], vmap[j], vr);

      STORE(&map[(i + j) * WORDS_IN_ZMM], vmap[j]);
    }
  }
}

// Convert from bytes representation where each byte holds a single bit
// to binary representation where each byte holds 8 bits of the polynomial
_INLINE_ void bytes_to_bin(OUT pad_r_t *bin_buf, IN const uint8_t *bytes_buf)
{
  uint64_t *bin64 = (uint64_t *)bin_buf;

  __m512i first_bit_mask = SET1_I8(1);
  for(size_t i = 0; i < R_QWORDS; i++) {
    __m512i t = LOAD(&bytes_buf[i * BYTES_IN_ZMM]);
    bin64[i]  = CMPM_U8(t, first_bit_mask, _MM_CMPINT_EQ);
  }
}

// Convert from binary representation where each byte holds 8 bits
// to byte representation where each byte holds a single bit of the polynomial
_INLINE_ void bin_to_bytes(OUT uint8_t *bytes_buf, IN const pad_r_t *bin_buf)
{
  const uint64_t *bin64 = (const uint64_t *)bin_buf;

  for(size_t i = 0; i < R_QWORDS; i++) {
    __m512i t = SET1MZ_I8(bin64[i], 1);
    STORE(&bytes_buf[i * BYTES_IN_ZMM], t);
  }
}

// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// By [1](Observation 1), if
//     a = sum_{j in supp(a)} x^j,
// then
//     a^(2^k) % (x^r - 1) = sum_{j in supp(a)} x^((j * 2^k) % r).
// Therefore, k-squaring can be computed as permutation of the bits of "a":
//     pi0 : j --> (j * 2^k) % r.
// For improved performance, we compute the result by inverted permutation pi1:
//     pi1 : (j * 2^-k) % r --> j.
// Input argument l_param is defined as the value (2^-k) % r.
void k_sqr_avx512(OUT pad_r_t *c, IN const pad_r_t *a, IN const size_t l_param)
{
  ALIGN(ALIGN_BYTES) uint16_t map[R_PADDED];
  ALIGN(ALIGN_BYTES) uint8_t  a_bytes[R_PADDED];
  ALIGN(ALIGN_BYTES) uint8_t  c_bytes[R_PADDED] = {0};

  // Generate the permutation map defined by pi1 and l_param.
  generate_map(map, l_param);

  bin_to_bytes(a_bytes, a);

  // Permute "a" using the generated permutation map.
  for(size_t i = 0; i < R_BITS; i++) {
    c_bytes[i] = a_bytes[map[i]];
  }

  bytes_to_bin(c, c_bytes);

  secure_clean(a_bytes, sizeof(a_bytes));
  secure_clean(c_bytes, sizeof(c_bytes));
}

#endif

typedef int dummy_typedef_to_avoid_empty_translation_unit_warning;
