/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#if !defined(RDTSC)
#  define MEASURE(msg, x) \
    do {                  \
      x                   \
    } while(0)
#else

#  include <float.h>
#  include <stdint.h>

// This part defines the functions and macros needed to measure using RDTSC
#  if !defined(REPEAT)
#    define REPEAT 100
#  endif

#  if !defined(OUTER_REPEAT)
#    define OUTER_REPEAT 10
#  endif

#  if !defined(WARMUP)
#    define WARMUP (REPEAT / 4)
#  endif

uint64_t               start_clk, end_clk;
double                 total_clk;
double                 temp_clk;
size_t                 rdtsc_itr;
size_t                 rdtsc_outer_itr;

#  define HALF_GPR_SIZE UINT8_C(32)

#  if defined(X86_64)
inline static uint64_t get_cycles(void)
{
  uint64_t hi;
  uint64_t lo;
  __asm__ __volatile__("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
  return lo ^ (hi << HALF_GPR_SIZE);
}
#  elif defined(AARCH64)
inline static uint64_t get_cycles(void)
{
  uint64_t value;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
  return value;
}
#  else
#    error "Unsupported architecture."
#  endif

/*
This MACRO measures the number of cycles "x" runs. This is the flow:
   1) it repeats "x" WARMUP times, in order to warm the cache.
   2) it reads the Time Stamp Counter at the beginning of the test.
   3) it repeats "x" REPEAT number of times.
   4) it reads the Time Stamp Counter again at the end of the test
   5) it calculates the average number of cycles per one iteration of "x", by
calculating the total number of cycles, and dividing it by REPEAT
 */
#  define MEASURE(msg, x)                                    \
    for(rdtsc_itr = 0; rdtsc_itr < WARMUP; rdtsc_itr++) {    \
      {x};                                                   \
    }                                                        \
    total_clk = DBL_MAX;                                     \
    for(rdtsc_outer_itr = 0; rdtsc_outer_itr < OUTER_REPEAT; \
        rdtsc_outer_itr++) {                                 \
      start_clk = get_cycles();                              \
      for(rdtsc_itr = 0; rdtsc_itr < REPEAT; rdtsc_itr++) {  \
        {x};                                                 \
      }                                                      \
      end_clk  = get_cycles();                               \
      temp_clk = (double)(end_clk - start_clk) / REPEAT;     \
      if(total_clk > temp_clk) total_clk = temp_clk;         \
    }                                                        \
    printf(msg);                                             \
    printf(" took %0.2f cycles\n", total_clk);

#endif
