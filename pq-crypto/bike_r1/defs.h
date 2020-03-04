/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

////////////////////////////////////////////
//             Basic defs
///////////////////////////////////////////
#define FUNC_PREFIX BIKE1_L1_R1
#include "functions_renaming.h"

#ifdef __cplusplus
#  define EXTERNC extern "C"
#else
#  define EXTERNC
#endif

// For code clarity.
#define IN
#define OUT

#define ALIGN(n)        __attribute__((aligned(n)))
#define BIKE_UNUSED(x)  (void)(x)
#define BIKE_UNUSED_ATT __attribute__((unused))

#define _INLINE_ static inline

// In asm the symbols '==' and '?' are not allowed therefore if using
// divide_and_ceil in asm files we must ensure with static_assert its validity
#if(__cplusplus >= 201103L) || defined(static_assert)
#  define bike_static_assert(COND, MSG) static_assert(COND, "MSG")
#else
#  define bike_static_assert(COND, MSG) \
    typedef char static_assertion_##MSG[(COND) ? 1 : -1] BIKE_UNUSED_ATT
#endif

// Divide by the divider and round up to next integer
#define DIVIDE_AND_CEIL(x, divider) (((x) + (divider)) / (divider))

#define BIT(len) (1ULL << (len))

#define MASK(len)      (BIT(len) - 1)
#define SIZEOF_BITS(b) (sizeof(b) * 8)

#define QW_SIZE  0x8
#define XMM_SIZE 0x10
#define YMM_SIZE 0x20
#define ZMM_SIZE 0x40

#define ALL_YMM_SIZE (16 * YMM_SIZE)
#define ALL_ZMM_SIZE (32 * ZMM_SIZE)

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
#define LOG2_MSB(v)                                                       \
  ((v) == 0                                                               \
       ? 0                                                                \
       : ((v) < 2                                                         \
              ? 1                                                         \
              : ((v) < 4                                                  \
                     ? 2                                                  \
                     : ((v) < 8                                           \
                            ? 3                                           \
                            : ((v) < 16                                   \
                                   ? 4                                    \
                                   : ((v) < 32                            \
                                          ? 5                             \
                                          : ((v) < 64 ? 6                 \
                                                      : ((v) < 128        \
                                                             ? 7          \
                                                             : ((v) < 256 \
                                                                    ? 8   \
                                                                    : 9)))))))))

////////////////////////////////////////////
//             Debug
///////////////////////////////////////////

#ifndef VERBOSE
#  define VERBOSE 0
#endif

#include <stdio.h>

#if(VERBOSE == 4)
#  define MSG(...)         \
    {                      \
      printf(__VA_ARGS__); \
    }
#  define DMSG(...)   MSG(__VA_ARGS__)
#  define EDMSG(...)  MSG(__VA_ARGS__)
#  define SEDMSG(...) MSG(__VA_ARGS__)
#elif(VERBOSE == 3)
#  define MSG(...)         \
    {                      \
      printf(__VA_ARGS__); \
    }
#  define DMSG(...)  MSG(__VA_ARGS__)
#  define EDMSG(...) MSG(__VA_ARGS__)
#  define SEDMSG(...)
#elif(VERBOSE == 2)
#  define MSG(...)         \
    {                      \
      printf(__VA_ARGS__); \
    }
#  define DMSG(...) MSG(__VA_ARGS__)
#  define EDMSG(...)
#  define SEDMSG(...)
#elif(VERBOSE == 1)
#  define MSG(...)         \
    {                      \
      printf(__VA_ARGS__); \
    }
#  define DMSG(...)
#  define EDMSG(...)
#  define SEDMSG(...)
#else
#  define MSG(...)
#  define DMSG(...)
#  define EDMSG(...)
#  define SEDMSG(...)
#endif

////////////////////////////////////////////
//              Printing
///////////////////////////////////////////
//#define PRINT_IN_BE
//#define NO_SPACE
//#define NO_NEWLINE
