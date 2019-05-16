/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.md, and applies to this file.
* ***************************************************************************/

#pragma once

#include "cleanup.h"

#ifndef bswap_64
  #define bswap_64(x) __builtin_bswap64(x)
#endif

// Printing values in Little Endian
void print_LE(IN const uint64_t *in, IN const uint32_t bits_num);

// Printing values in Big Endian
void print_BE(IN const uint64_t *in, IN const uint32_t bits_num);

// Printing number is required only in verbose level 2 or above
#if VERBOSE>=2
  #ifdef PRINT_IN_BE
    // Print in Big Endian
    #define print(in, bits_num) print_BE(in, bits_num)
  #else
    // Print in Little Endian
    #define print(in, bits_num) print_LE(in, bits_num)
  #endif
#else
  // No prints at all
  #define print(in, bits_num)
#endif

// Comparing value in a constant time manner
_INLINE_ uint32_t safe_cmp(IN const uint8_t *a,
                           IN const uint8_t *b,
                           IN const uint32_t size)
{
  volatile uint8_t res = 0;

  for(uint32_t i=0; i < size; ++i)
  {
    res |= (a[i] ^ b[i]);
  }

  return (0 == res);
}

// Constant time
_INLINE_ uint32_t iszero(IN const uint8_t *s, IN const uint32_t len)
{
    volatile uint32_t res = 0;
    for (uint64_t i = 0; i < len; i++)
    {
        res |= s[i];
    }
    return (0 == res);
}

// BSR returns ceil(log2(val))
_INLINE_ uint8_t bit_scan_reverse(uint64_t val)
{
    // index is always smaller than 64
    uint8_t index = 0;

    while(val != 0)
    {
        val >>= 1;
        index++;
    }

    return index;
}

// Return 1 if equal 0 otherwise
_INLINE_ uint32_t secure_cmp32(IN const uint32_t v1, IN const uint32_t v2)
{
    uint32_t res;
    __asm__ __volatile__("xor  %%edx, %%edx; \n"
                         "cmp  %1, %2; \n "
                         "sete %%dl; \n"
                         "mov %%edx, %0; \n"
                         : "=r" (res)
                         : "r"(v1), "r"(v2)
                         : "rdx");
    
    return res;
}

// Return 1 if v1 >= v2, 0 otherwise
_INLINE_ uint32_t secure_ge32(IN const uint32_t v1, IN const uint32_t v2)
{
    uint32_t res;
    __asm__ __volatile__("xor  %%edx, %%edx; \n"
                         "cmp  %1, %2; \n "
                         "setge %%dl; \n"
                         "mov %%edx, %0; \n"
                         : "=r" (res)
                         : "r"(v2), "r"(v1)
                         : "rdx");
    
    return res;
}

// Return 0 if v1 < v2, (-1) otherwise
_INLINE_ uint32_t secure_l32_mask(IN const uint32_t v1, IN const uint32_t v2)
{
    uint32_t res;
    __asm__ __volatile__("xor  %%edx, %%edx; \n"
                         "cmp  %1, %2; \n "
                         "setl %%dl; \n"
                         "dec %%edx; \n"
                         "mov %%edx, %0; \n"
                         
                         : "=r" (res)
                         : "r"(v2), "r"(v1)
                         : "rdx");
    
    return res;
}

// len is bytes length of in
EXTERNC uint64_t count_ones(IN const uint8_t *in, IN const uint32_t len);
