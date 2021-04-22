/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

// For memset
#include <string.h>

#include "types.h"

uint64_t r_bits_vector_weight(IN const r_t *in);

// "VALUE_BARRIER returns |a|, but prevents GCC and Clang from reasoning about
// the returned value. This is used to mitigate compilers undoing constant-time
// code, until we can express our requirements directly in the language.
// Note the compiler is aware that |VALUE_BARRIER| has no side effects and
// always has the same output for a given input. This allows it to eliminate
// dead code, move computations across loops, and vectorize."
// See:
// https://github.com/google/boringssl/commit/92b7c89e6e8ba82924b57153bea68241cc45f658
#if(defined(__GNUC__) || defined(__clang__))
#  define VALUE_BARRIER(name, type)            \
    _INLINE_ type name##_barrier(type a)       \
    {                                          \
      __asm__("" : "+r"(a) : /* no inputs */); \
      return a;                                \
    }
#else
#  define VALUE_BARRIER(name, type) \
    _INLINE_ type name##_barrier(type a) { return a; }
#endif

VALUE_BARRIER(u8, uint8_t)
VALUE_BARRIER(u32, uint32_t)
VALUE_BARRIER(u64, uint64_t)

// Comparing value in a constant time manner
_INLINE_ uint32_t secure_cmp(IN const uint8_t *a,
                             IN const uint8_t *b,
                             IN const uint32_t size)
{
  volatile uint8_t res = 0;

  for(uint32_t i = 0; i < size; ++i) {
    res |= (a[i] ^ b[i]);
  }

  return (0 == res);
}

// Return 1 if the arguments are equal to each other. Return 0 otherwise.
_INLINE_ uint32_t secure_cmp32(IN const uint32_t v1, IN const uint32_t v2)
{
#if defined(__aarch64__)
  uint32_t res;
  __asm__ __volatile__("cmp  %w[V1], %w[V2]; \n "
                       "cset %w[RES], EQ; \n"
                       : [RES] "=r"(res)
                       : [V1] "r"(v1), [V2] "r"(v2)
                       : "cc" /*The condition code flag*/);
  return res;
#elif defined(__x86_64__) || defined(__i386__)
  uint32_t res;
  __asm__ __volatile__("xor  %%edx, %%edx; \n"
                       "cmp  %1, %2; \n "
                       "sete %%dl; \n"
                       "mov %%edx, %0; \n"
                       : "=r"(res)
                       : "r"(v1), "r"(v2)
                       : "rdx");
  return res;
#else
  // Insecure comparison: The main purpose of secure_cmp32 is to avoid
  // branches to prevent potential side channel leaks. To do that,
  // we normally leverage some special CPU instructions such as "sete"
  // (for __x86_64__) and "cset" (for __aarch64__). When dealing with general
  // CPU architectures, the interpretation of the line below is left for the
  // compiler. It could lead to an "insecure" branch. This case needs to be
  // checked individually on such platforms
  // (e.g., by checking the compiler-generated assembly).
  return (v1 == v2 ? 1 : 0);
#endif
}

// Return 0 if v1 < v2, (-1) otherwise
_INLINE_ uint32_t secure_l32_mask(IN const uint32_t v1, IN const uint32_t v2)
{
#if defined(__aarch64__)
  uint32_t res;
  __asm__ __volatile__("cmp  %w[V2], %w[V1]; \n "
                       "cset %w[RES], HI; \n"
                       : [RES] "=r"(res)
                       : [V1] "r"(v1), [V2] "r"(v2)
                       : "cc" /*The condition code flag*/);
  return (res - 1);
#elif defined(__x86_64__) || defined(__i386__)
  uint32_t res;
  __asm__ __volatile__("xor  %%edx, %%edx; \n"
                       "cmp  %1, %2; \n "
                       "setl %%dl; \n"
                       "dec %%edx; \n"
                       "mov %%edx, %0; \n"

                       : "=r"(res)
                       : "r"(v2), "r"(v1)
                       : "rdx");

  return res;
#else
  // If v1 >= v2 then the subtraction result is 0^32||(v1-v2).
  // else it is 1^32||(v2-v1+1). Subsequently, negating the upper
  // 32 bits gives 0 if v1 < v2 and otherwise (-1).
  return ~((uint32_t)(((uint64_t)v1 - (uint64_t)v2) >> 32));
#endif
}

// bike_memcpy avoids the undefined behaviour of memcpy when byte_len=0
_INLINE_ void *bike_memcpy(void *dst, const void *src, size_t byte_len)
{
  if(byte_len == 0) {
    return dst;
  }

  return memcpy(dst, src, byte_len);
}

// bike_memset avoids the undefined behaviour of memset when byte_len=0
_INLINE_ void *bike_memset(void *dst, const int ch, size_t byte_len)
{
  if(byte_len == 0) {
    return dst;
  }

  return memset(dst, ch, byte_len);
}
