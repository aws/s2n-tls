/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "defs.h"

////////////////////////////////////////////
//             BIKE Parameters
///////////////////////////////////////////
#define N0 2

#if !defined(LEVEL)
#  define LEVEL 1
#endif

#if(LEVEL == 3)
#  define R_BITS 24659
#  define DV      103
#  define T1      199

#  define THRESHOLD_COEFF0 15.2588
#  define THRESHOLD_COEFF1 0.005265
#  define THRESHOLD_MIN    52

// The gf2m code is optimized to a block in this case:
#  define BLOCK_BITS 32768
#elif (LEVEL == 1)
// 64-bits of post-quantum security parameters (BIKE paper):
#  define R_BITS 12323
#  define DV      71
#  define T1      134

#  define THRESHOLD_COEFF0 13.530
#  define THRESHOLD_COEFF1 0.0069722
#  define THRESHOLD_MIN    36

// The gf2x code is optimized to a block in this case:
#  define BLOCK_BITS       (16384)
#else
#  error "Bad level, choose one of 1/3/5"
#endif

#define NUM_OF_SEEDS 2

// Round the size to the nearest byte.
// SIZE suffix, is the number of bytes (uint8_t).
#define N_BITS   (R_BITS * N0)
#define R_BYTES  DIVIDE_AND_CEIL(R_BITS, 8)
#define R_QWORDS DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_QWORD)
#define R_XMM    DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_XMM)
#define R_YMM    DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_YMM)
#define R_ZMM    DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_ZMM)

#define R_BLOCKS        DIVIDE_AND_CEIL(R_BITS, BLOCK_BITS)
#define R_PADDED        (R_BLOCKS * BLOCK_BITS)
#define R_PADDED_BYTES  (R_PADDED / 8)
#define R_PADDED_QWORDS (R_PADDED / 64)

#define LAST_R_QWORD_LEAD  (R_BITS & MASK(6))
#define LAST_R_QWORD_TRAIL (64 - LAST_R_QWORD_LEAD)
#define LAST_R_QWORD_MASK  MASK(LAST_R_QWORD_LEAD)

#define LAST_R_BYTE_LEAD  (R_BITS & MASK(3))
#define LAST_R_BYTE_TRAIL (8 - LAST_R_BYTE_LEAD)
#define LAST_R_BYTE_MASK  MASK(LAST_R_BYTE_LEAD)

// Data alignement
#define ALIGN_BYTES (BYTES_IN_ZMM)

#define M_BITS  256
#define M_BYTES (M_BITS / 8)

#define SS_BITS  256
#define SS_BYTES (SS_BITS / 8)

#define SEED_BYTES (256 / 8)

//////////////////////////////////
// Parameters for the BGF decoder.
//////////////////////////////////
#define BGF_DECODER
#define DELTA  3
#define SLICES (LOG2_MSB(DV) + 1)

// GF2X inversion can only handle R < 32768
bike_static_assert((R_BITS < 32768), r_too_large_for_inversion);
