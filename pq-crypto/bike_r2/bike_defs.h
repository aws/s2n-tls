/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#pragma once

#include "defs.h"

#define LEVEL 1

////////////////////////////////////////////
//             BIKE Parameters
///////////////////////////////////////////
#define N0 2

#ifndef LEVEL
#  define LEVEL 1
#endif

#if(LEVEL == 3)
#  ifdef INDCPA
#    define R_BITS 19853
#  else
#    define R_BITS 24821
#  endif
#  define DV 103
#  define T1 199

#  define THRESHOLD_COEFF0 15.932
#  define THRESHOLD_COEFF1 0.0052936

// The gfm code is optimized to a block size in this case:
#  define BLOCK_SIZE 32768
#elif(LEVEL == 1)
// 64-bits of post-quantum security parameters (BIKE paper):
#  ifdef INDCPA
#    define R_BITS 10163
#  else
#    define R_BITS 11779
#  endif
#  define DV 71
#  define T1 134

#  define THRESHOLD_COEFF0 13.530
#  define THRESHOLD_COEFF1 0.0069721

// The gfm code is optimized to a block size in this case:
#  define BLOCK_SIZE       (16384)
#else
#  error "Bad level, choose one of 1/3"
#endif

#ifdef INDCPA
#  define NUM_OF_SEEDS 2
#else
#  define NUM_OF_SEEDS 3
#endif

// Round the size to the nearest byte.
// SIZE suffix, is the number of bytes (uint8_t).
#define N_BITS (R_BITS * N0)
#define R_SIZE DIVIDE_AND_CEIL(R_BITS, 8)
#define R_QW   DIVIDE_AND_CEIL(R_BITS, 8 * QW_SIZE)
#define R_YMM  DIVIDE_AND_CEIL(R_BITS, 8 * YMM_SIZE)
#define R_ZMM  DIVIDE_AND_CEIL(R_BITS, 8 * ZMM_SIZE)

#define N_SIZE DIVIDE_AND_CEIL(N_BITS, 8)

#define R_BLOCKS      DIVIDE_AND_CEIL(R_BITS, BLOCK_SIZE)
#define R_PADDED      (R_BLOCKS * BLOCK_SIZE)
#define R_PADDED_SIZE (R_PADDED / 8)
#define R_PADDED_QW   (R_PADDED / 64)

#define N_BLOCKS      DIVIDE_AND_CEIL(N_BITS, BLOCK_SIZE)
#define N_PADDED      (N_BLOCKS * BLOCK_SIZE)
#define N_PADDED_SIZE (N_PADDED / 8)
#define N_PADDED_QW   (N_PADDED / 64)

#define R_DDQWORDS_BITS (DIVIDE_AND_CEIL(R_BITS, ALL_YMM_SIZE) * ALL_YMM_SIZE)
bike_static_assert((R_BITS % ALL_YMM_SIZE != 0), rbits_512_err);

#define N_DDQWORDS_BITS (R_DDQWORDS_BITS + R_BITS)
bike_static_assert((N_BITS % ALL_YMM_SIZE != 0), nbits_512_err);

#define LAST_R_QW_LEAD  (R_BITS & MASK(6))
#define LAST_R_QW_TRAIL (64 - LAST_R_QW_LEAD)
#define LAST_R_QW_MASK  MASK(LAST_R_QW_LEAD)

#define LAST_R_BYTE_LEAD  (R_BITS & MASK(3))
#define LAST_R_BYTE_TRAIL (8 - LAST_R_BYTE_LEAD)
#define LAST_R_BYTE_MASK  MASK(LAST_R_BYTE_LEAD)

// BIKE auxiliary functions parameters:
#define ELL_K_BITS 256
#define ELL_K_SIZE (ELL_K_BITS / 8)

////////////////////////////////
// Parameters for the BG decoder.
////////////////////////////////
#define DELTA  3
#define SLICES (LOG2_MSB(DV) + 1)

#define BGF_DECODER
