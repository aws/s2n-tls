/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.txt, and applies to this file.
* ***************************************************************************/

#ifndef __BIKE_DEFS_H_INCLUDED__
#define __BIKE_DEFS_H_INCLUDED__

#include "defs.h"

#if BIKE_VER > 3
  Error bad "BIKE_VER" value !
#endif

////////////////////////////////////////////
//             BIKE Parameters
///////////////////////////////////////////
#define N0 2

#ifndef LEVEL
  #define LEVEL 5
#endif

#if (BIKE_VER == 3)
  #if (LEVEL == 5)
    // 128-bits of post-quantum security parameters:
    #define R_BITS  36131
    #define DV      133
    #define FAKE_DV 261
    #define T1      300
    
    #define BLOCK_SIZE (32768 * 2)
  #elif (LEVEL == 3)
    // 96-bits of post-quantum security parameters:
    #define R_BITS  21683
    #define DV      99
    #define FAKE_DV 197
    #define T1      226
      
    #define BLOCK_SIZE (32768)
  #elif (LEVEL == 1)
    // 64-bits of post-quantum security parameters:
    #define R_BITS  11027
    #define DV      67
    #define FAKE_DV 132
    #define T1      154
        
    #define BLOCK_SIZE (16384)
  #endif
#else
  #if (LEVEL == 5)
    // 128-bits of post-quantum security parameters (BIKE paper):
    // Increased r for better DFR
    #define R_BITS  32749
    #define DV      137
    #define FAKE_DV 261
    #define T1      264
    
    // The gfm code is optimized to a block size in this case:
    #define BLOCK_SIZE (32768)
  #elif (LEVEL == 3)
    #define R_BITS  19853
    #define DV      103
    #define FAKE_DV 197
    #define T1      199

    // The gfm code is optimized to a block size in this case:
    #define BLOCK_SIZE (32768)
  #elif (LEVEL == 1)
    // 64-bits of post-quantum security parameters (BIKE paper):
    // REDUCED SIZES to make the proofs tractable
    #define R_BITS  163 // more than 128 so we use multiple quadwords
    #define DV      3
    #define FAKE_DV 4
    #define T1      7

    //The gfm code is optimized to a block size in this case:
    #define BLOCK_SIZE (512) // larger than R_BITS, as in the full-sized version
  #else
    #error "Bad level, choose one of 1/3/5"
  #endif
#endif

#define MAX_DELTA 4

// For BIKE-1 and BIKE-2, u = 0 (i.e. syndrome must become a zero-vector)
// For BIKE-3, u = t/2
#if BIKE_VER==3
    #define U_ERR (T1 / 2)
#else
    #define U_ERR 0
#endif

// Batch count for simulation inversion
#ifndef BATCH_SIZE
    #define BATCH_SIZE 1
#endif

#if (BATCH_SIZE > 1) && (BIKE_VER != 2)
    Error BATCH SIZE is ignored when BIKE VER != 2.
#endif

//Round the size to the nearest byte.
//SIZE suffix, is the number of bytes (uint8_t).
#define N_BITS   (R_BITS * N0)
#define R_SIZE   DIVIDE_AND_CEIL(R_BITS, 8)
#define R_QW     DIVIDE_AND_CEIL(R_BITS, 64)
#define N_SIZE   DIVIDE_AND_CEIL(N_BITS, 8)
#define N_QW     DIVIDE_AND_CEIL(N_BITS, 64)
#define N_EXTRA_BYTES (8 * N_QW - N_SIZE)

#define R_BLOCKS         DIVIDE_AND_CEIL(R_BITS, BLOCK_SIZE)
#define R_PADDED        (R_BLOCKS * BLOCK_SIZE)
#define R_PADDED_SIZE   (R_PADDED / 8)
#define R_PADDED_QW     (R_PADDED / 64)

#define N_BLOCKS         DIVIDE_AND_CEIL(N_BITS, BLOCK_SIZE)
#define N_PADDED        (N_BLOCKS * BLOCK_SIZE)
#define N_PADDED_SIZE   (N_PADDED / 8)
#define N_PADDED_QW     (N_PADDED / 64)

#define R_DQWORDS DIVIDE_AND_CEIL(R_SIZE, 16)

#ifdef AVX512
#define R_QDQWORDS_BITS (DIVIDE_AND_CEIL(R_BITS, ALL_ZMM_SIZE) * ALL_ZMM_SIZE)
bike_static_assert((R_BITS % ALL_ZMM_SIZE != 0), rbits_2048_err);

#define N_QDQWORDS_BITS (R_QDQWORDS_BITS + R_BITS)
bike_static_assert((N_BITS % ALL_ZMM_SIZE != 0), nbits_2048_err);

#else //AVX512

#define R_DDQWORDS_BITS (DIVIDE_AND_CEIL(R_BITS, ALL_YMM_SIZE) * ALL_YMM_SIZE)
bike_static_assert((R_BITS % ALL_YMM_SIZE != 0), rbits_512_err);

#define N_DDQWORDS_BITS (R_DDQWORDS_BITS + R_BITS)
bike_static_assert((N_BITS % ALL_YMM_SIZE != 0), nbits_512_err);

#endif

#define LAST_R_QW_LEAD  (R_BITS & MASK(6))
#define LAST_R_QW_TRAIL (64 - LAST_R_QW_LEAD)
#define LAST_R_QW_MASK  MASK(LAST_R_QW_LEAD)

#define LAST_R_BYTE_LEAD  (R_BITS & MASK(3))
#define LAST_R_BYTE_TRAIL (8 - LAST_R_BYTE_LEAD)
#define LAST_R_BYTE_MASK  MASK(LAST_R_BYTE_LEAD)

// BIKE auxiliary functions parameters:
#define ELL_K_BITS  256
#define ELL_K_SIZE (ELL_K_BITS / 8)

#define SHA_MB_SECURE_BUF_SIZE 608

#endif //__BIKE_DEFS_H_INCLUDED__

