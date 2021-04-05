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

#include "cleanup.h"
#include "gf2x_internal.h"

#define NUM_YMMS    (2)
#define NUM_OF_VALS (NUM_YMMS * WORDS_IN_YMM)

void generate_map(OUT uint16_t *map, IN const uint16_t l_param)
{
  __m256i vmap[NUM_YMMS], vtmp[NUM_YMMS], vr, inc, zero;

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

  vr   = SET1_I16(R_BITS);
  zero = SET_ZERO;

  // Set the increment vector such that adding it to vmap vectors
  // gives the next NUM_OF_VALS elements of the map. AVX2 does not
  // support comparison of vectors where vector elements are considered
  // as unsigned integers. This is a problem when r > 2^14 because
  // sum of two values can be greater than 2^15 which would make the it
  // a negative number when considered as a signed 16-bit integer,
  // and therefore, the condition in step 4 of the algorithm would be
  // evaluated incorrectly. So, we use the following trick:
  // we subtract R from the increment and modify the algorithm:
  //   1. map[0] = l_param
  //   2. for i = 1 to map size:
  //   3.   map[i] = map[i - 1] + (l_param - r)
  //   4.   if map[i] < 0:
  //   5.     map[i] = map[i] + r
  inc = SET1_I16((l_param * NUM_OF_VALS) % R_BITS);
  inc = SUB_I16(inc, vr);

  // Load the first NUM_OF_VALS elements in the vmap vectors
  for(size_t i = 0; i < NUM_YMMS; i++) {
    vmap[i] = LOAD(&map[i * WORDS_IN_YMM]);
  }

  for(size_t i = NUM_YMMS; i < (R_PADDED / WORDS_IN_YMM); i += NUM_YMMS) {
    for(size_t j = 0; j < NUM_YMMS; j++) {
      vmap[j] = ADD_I16(vmap[j], inc);
      vtmp[j] = CMPGT_I16(zero, vmap[j]);
      vmap[j] = ADD_I16(vmap[j], vtmp[j] & vr);

      STORE(&map[(i + j) * WORDS_IN_YMM], vmap[j]);
    }
  }
}

// Convert from bytes representation, where every byte holds a single bit,
// of the polynomial, to a binary representation where every byte
// holds 8 bits of the polynomial.
_INLINE_ void bytes_to_bin(OUT pad_r_t *bin_buf, IN const uint8_t *bytes_buf)
{
  uint32_t *bin32 = (uint32_t *)bin_buf;

  for(size_t i = 0; i < R_QWORDS * 2; i++) {
    __m256i t = LOAD(&bytes_buf[i * BYTES_IN_YMM]);
    bin32[i]  = MOVEMASK(t);
  }
}

// Convert from binary representation where every byte holds 8 bits
// of the polynomial, to byte representation where
// every byte holds a single bit of the polynomial.
_INLINE_ void bin_to_bytes(OUT uint8_t *bytes_buf, IN const pad_r_t *bin_buf)
{
  // The algorithm works by taking every 32 bits of the input and converting
  // them to 32 bytes where each byte holds one of the bits. The first step is
  // to broadcast a 32-bit value (call it a)  to all elements of vector t.
  // Then t contains bytes of a in the following order:
  //   t = [ a3 a2 a1 a0 ... a3 a2 a1 a0 ]
  // where a0 contains the first 8 bits of a, a1 the second 8 bits, etc.
  // Let the output vector be [ out31 out30 ... out0 ]. We want to store
  // bit 0 of a in out0 byte, bit 1 of a in out1 byte, ect. (note that
  // we want to store the bit in the most significant position of a byte
  // because this is required by MOVEMASK instruction used in bytes_to_bin.)
  //
  // Ideally, we would shuffle the bytes of t such that the byte in
  // i-th position contains i-th bit of val, shift t appropriately and obtain
  // the result. However, AVX2 doesn't support shift operation on bytes, only
  // shifts of individual QWORDS (64 bit) and DWORDS (32 bit) are allowed.
  // Consider the two least significant DWORDS of t:
  //   t = [ ... | a3 a2 a1 a0 | a3 a2 a1 a0 ]
  // and shift them by 6 and 4 to the left, respectively, to obtain:
  //   t = [ ... | t7 t6 t5 t4 | t3 t2 t1 t0 ]
  // where t3 = a3 << 6, t2 = a2 << 6, t1 = a1 << 6, t0 = a0 << 6,
  // and   t7 = a3 << 4, t6 = a2 << 4, t5 = a1 << 4, t4 = a0 << 4.
  // Now we shuffle vector t to obtain vector p such that:
  //   p = [ ... | t12 t12 t8 t8 | t4 t4 t0 t0 ]
  // Note that in every even position of the vector p we have the right byte
  // of the input shifted by the required shift. The values in the odd
  // positions contain the right bytes of the input but they need to be shifted
  // one more time to the left by 1. By shifting each DWORD of p by 1 we get:
  //   q = [ ... | p7 p6 p5 p4 | p3 p2 p1 p0 ]
  // where p1 = t0 << 1 = a0 << 7, p3 = t4 << 1 = 5, etc. Therefore, by
  // blending p and q (taking even positions from p and odd positions from q)
  // we obtain the desired result.

  __m256i t, p, q;

  const __m256i shift_mask = SET_I32(0, 2, 4, 6, 0, 2, 4, 6);

  const __m256i shuffle_mask =
    SET_I8(15, 15, 11, 11, 7, 7, 3, 3, 14, 14, 10, 10, 6, 6, 2, 2, 13, 13, 9, 9,
           5, 5, 1, 1, 12, 12, 8, 8, 4, 4, 0, 0);

  const __m256i blend_mask = SET1_I16(0x00ff);

  const uint32_t *bin32 = (const uint32_t *)bin_buf;

  for(size_t i = 0; i < R_QWORDS * 2; i++) {
    t = SET1_I32(bin32[i]);
    t = SLLV_I32(t, shift_mask);

    p = SHUF_I8(t, shuffle_mask);
    q = SLLI_I32(p, 1);

    STORE(&bytes_buf[i * 32], BLENDV_I8(p, q, blend_mask));
  }
}

// The k-squaring function computes c = a^(2^k) % (x^r - 1).
// By [1](Observation 1), if
//     a = sum_{j in supp(a)} x^j,
// then
//     a^(2^k) % (x^r - 1) = sum_{j in supp(a)} x^((j * 2^k) % r).
// Therefore, k-squaring can be computed as permutation of the bits of "a":
//     pi0 : j --> (j * 2^k) % r.
// For improved performance, we compute the result by inverted permutation pi1:
//     pi1 : (j * 2^-k) % r --> j.
// Input argument l_param is defined as the value (2^-k) % r.
void k_squaring(OUT pad_r_t *c, IN const pad_r_t *a, IN const size_t l_param)
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
