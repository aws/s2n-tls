/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

////////////////////////////////////////////
//             Basic defs
///////////////////////////////////////////

// For code clarity.
#define IN
#define OUT

#define ALIGN(n)        __attribute__((aligned(n)))
#define BIKE_UNUSED_ATT __attribute__((unused))

#define _INLINE_ static inline

// In asm the symbols '==' and '?' are not allowed. Therefore, if using
// divide_and_ceil in asm files, we must ensure with static_assert its validity.
#if(__cplusplus >= 201103L) || defined(static_assert)
#  define bike_static_assert(COND, MSG) static_assert(COND, "MSG")
#else
#  define bike_static_assert(COND, MSG) \
    typedef char static_assertion_##MSG[(COND) ? 1 : -1] BIKE_UNUSED_ATT
#endif

// Divide by the divider and round up to next integer
#define DIVIDE_AND_CEIL(x, divider) (((x) + (divider)-1) / (divider))

// Bit manipulations
// Linux Assemblies, except for Ubuntu, cannot understand what ULL mean.
// Therefore, in that case len must be smaller than 31.
#define BIT(len)       (1ULL << (len))
#define MASK(len)      (BIT(len) - 1)
#define SIZEOF_BITS(b) (sizeof(b) * 8)

#define BYTES_IN_QWORD 0x8
#define BYTES_IN_XMM   0x10
#define BYTES_IN_YMM   0x20
#define BYTES_IN_ZMM   0x40

#define BITS_IN_YMM (BYTES_IN_YMM * 8)
#define BITS_IN_ZMM (BYTES_IN_ZMM * 8)

#define WORDS_IN_YMM (BYTES_IN_YMM / sizeof(uint16_t))
#define WORDS_IN_ZMM (BYTES_IN_ZMM / sizeof(uint16_t))

#define DWORDS_IN_YMM (BYTES_IN_YMM / sizeof(uint32_t))
#define DWORDS_IN_ZMM (BYTES_IN_ZMM / sizeof(uint32_t))

#define QWORDS_IN_XMM (BYTES_IN_XMM / sizeof(uint64_t))
#define QWORDS_IN_YMM (BYTES_IN_YMM / sizeof(uint64_t))
#define QWORDS_IN_ZMM (BYTES_IN_ZMM / sizeof(uint64_t))

// Copied from (Kaz answer)
// https://stackoverflow.com/questions/466204/rounding-up-to-next-power-of-2
#define UPTOPOW2_0(v) ((v)-1)
#define UPTOPOW2_1(v) (UPTOPOW2_0(v) | (UPTOPOW2_0(v) >> 1))
#define UPTOPOW2_2(v) (UPTOPOW2_1(v) | (UPTOPOW2_1(v) >> 2))
#define UPTOPOW2_3(v) (UPTOPOW2_2(v) | (UPTOPOW2_2(v) >> 4))
#define UPTOPOW2_4(v) (UPTOPOW2_3(v) | (UPTOPOW2_3(v) >> 8))
#define UPTOPOW2_5(v) (UPTOPOW2_4(v) | (UPTOPOW2_4(v) >> 16))

#define UPTOPOW2(v) (UPTOPOW2_5(v) + 1)

// Works only for 0 < v < 512
#define LOG2_MSB(v)                                 \
  ((v) == 0                                         \
     ? 0                                            \
     : ((v) < 2                                     \
          ? 1                                       \
          : ((v) < 4                                \
               ? 2                                  \
               : ((v) < 8                           \
                    ? 3                             \
                    : ((v) < 16                     \
                         ? 4                        \
                         : ((v) < 32                \
                              ? 5                   \
                              : ((v) < 64           \
                                   ? 6              \
                                   : ((v) < 128 ? 7 \
                                                : ((v) < 256 ? 8 : 9)))))))))

#define REG_T uint64_t
#define LOAD(mem)       (mem)[0]
#define STORE(mem, val) (mem)[0] = val
#define SLLI_I64(a, imm) ((a) << (imm))
#define SRLI_I64(a, imm) ((a) >> (imm))

// NOLINT is used to avoid the sizeof(T)/sizeof(T) warning when REG_T is defined
// to be uint64_t
#define REG_QWORDS (sizeof(REG_T) / sizeof(uint64_t)) // NOLINT
#define REG_DWORDS (sizeof(REG_T) / sizeof(uint32_t)) // NOLINT

////////////////////////////////////////////
//             Debug
///////////////////////////////////////////

#if defined(VERBOSE)
#  include <stdio.h>

#  define DMSG(...)        \
    {                      \
      printf(__VA_ARGS__); \
    }
#else
#  define DMSG(...)
#endif

////////////////////////////////////////////
//              Printing
///////////////////////////////////////////
//#define PRINT_IN_BE
//#define NO_SPACE
//#define NO_NEWLINE
