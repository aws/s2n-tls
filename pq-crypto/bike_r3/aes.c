/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#if !defined(__AES__) || !defined(__SSSE3__)
#  error "This code requries support for AES_NI and SSSE3"
#endif

#include "aes.h"
#include "utilities.h"

#define AESENC(m, key)     (_mm_aesenc_si128(m, key))
#define AESENCLAST(m, key) (_mm_aesenclast_si128(m, key))

// The loadu and storeu intrinsic are designed to handle unaligned memory access.
// Therefore, we use the (void*) cast to disable the cast-align warning.
#define LOAD128(mem)       (_mm_loadu_si128((const void *)(mem)))
#define STORE128(mem, reg) (_mm_storeu_si128((void *)(mem), reg))

#define SETR128_I8(...)      (_mm_setr_epi8(__VA_ARGS__))
#define SETONE128_I32(a)     (_mm_set1_epi32(a))
#define SHUF128_I8(a, mask)  (_mm_shuffle_epi8(a, mask))
#define SHUF128_I32(a, mask) (_mm_shuffle_epi32(a, mask))
#define SLL128_I32(a, mask)  (_mm_slli_epi32(a, mask))
#define SLL128_I128(a, mask) (_mm_slli_si128(a, mask))

ret_t aes256_enc(OUT uint8_t *ct, IN const uint8_t *pt, IN const aes256_ks_t *ks)
{
  uint32_t i = 0;
  __m128i  block =
    SETR128_I8(pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7], pt[8],
               pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]);

  block ^= ks->keys[0];
  for(i = 1; i < AES256_ROUNDS; i++) {
    block = AESENC(block, ks->keys[i]);
  }
  block = AESENCLAST(block, ks->keys[AES256_ROUNDS]);

  STORE128(ct, block);

  return SUCCESS;
}

#define ROUND(in, t)          \
  do {                        \
    (t) = SLL128_I128(in, 4); \
    (in) ^= (t);              \
    (t) = SLL128_I128(t, 4);  \
    (in) ^= (t);              \
    (t) = SLL128_I128(t, 4);  \
  } while(0)

ret_t aes256_key_expansion(OUT aes256_ks_t *ks, IN const aes256_key_t *key)
{
  // Rotation: [b0, b1, b2, b3] --> [b1, b2, b3, b0]
  const __m128i rotation_mask = SETONE128_I32(0x0c0f0e0d);

  __m128i con = SETONE128_I32(1);
  __m128i t1;
  __m128i t2;

  ks->keys[0] = LOAD128(&key->raw[0]);
  ks->keys[1] = LOAD128(&key->raw[BYTES_IN_XMM]);

  __m128i in0 = ks->keys[0];
  __m128i in1 = ks->keys[1];

  for(size_t i = 0; i < 6; i++) {
    // Odd rounds
    t1  = AESENCLAST(SHUF128_I8(in1, rotation_mask), con);
    con = SLL128_I32(con, 1);
    ROUND(in0, t2);
    in0 ^= t2 ^ t1;
    ks->keys[2 * (i + 1) + 0] = in0;

    // Even rounds
    t1 = AESENCLAST(SHUF128_I32(in0, 0xff), _mm_setzero_si128());
    ROUND(in1, t2);
    in1 ^= t2 ^ t1;
    ks->keys[2 * (i + 1) + 1] = in1;
  }

  t1 = SHUF128_I8(in1, rotation_mask);
  t1 = AESENCLAST(t1, con);
  ROUND(in0, t2);
  in0 ^= t2 ^ t1;
  ks->keys[AES256_ROUNDS] = in0;

  return SUCCESS;
}
